# `libtopfollow.so` — Reverse Engineering Report

**Target:** `TopFollow_v845-Beta.apk` → `lib/arm64-v8a/libtopfollow.so`
**Analysed:** 2026-09-12 · static analysis only (no execution, no debugger)
**Scope:** obfuscation techniques · detection mechanisms · all encryption (AES + everything else)

---

## 0. Executive summary

| | |
|---|---|
| Library | `libtopfollow.so`, 1,805,400 bytes, AArch64 ELF shared object |
| Toolchain | Android NDK **r23c**, clang/LLD **12.0.9**, build-id `8568313…` |
| Symbols | **Stripped.** Exactly **one** export: `JNI_OnLoad @ 0x3e1d4`. 92 dynamic imports. |
| Code | 1,090 functions, **395,331 instructions** recovered |
| Obfuscator | A **control-flow-flattening + MBA + string-encryption** obfuscator (LLVM-style, OLLVM/Pluto/Armariris class). 12 flattened functions = **50.8 % of all code**. |
| Crypto | **AES (LibTomCrypt, T-table)** + **SHA-256 (LibTomCrypt)** + **Base64 (multi-layer)** + **single-byte XOR string encryption** |
| Hardcoded secret | **AES-256 key (32 B) @ `.rodata:0x17428`** and **IV (16 B) @ `.rodata:0x17448`** — embedded in the binary, see §4.2 |
| Detection | anti-Frida, anti-Xposed/LSPosed/EdXposed/Riru/Zygisk/Substrate, root (`su` paths), `/proc/self/maps` integrity (`rwxp`, `(deleted)` libs), APK signature check, device fingerprinting, certificate pinning, `clock()` timing |
| App | `com.nivaroid.topfollow` v8.4.5 (845), minSdk 24 / targetSdk 35. An Instagram follower/exchange panel client that talks to `i.instagram.com/api/v2/` and `www.instagram.com/graphql/query`. |

**Bottom line:** this is a professionally hardened JNI crypto+anti-tamper blob. Its only real secret is a **static AES-256 key/IV baked into `.rodata`**, which means any traffic it protects is decryptable by anyone who extracts the library. The obfuscation is expensive (huge flattened functions) but shallow (single-byte XOR, one MBA idiom, one CFF pass).

---

## 1. Target inventory

### 1.1 ELF layout (arm64-v8a)

| Section | Range | Size | Notes |
|---|---|---|---|
| `.rodata` | `0x0118b0 – 0x01ab5b` | 37,547 | **all crypto tables + all encrypted strings** |
| `.gcc_except_table` | `0x01ab5c – 0x021224` | 26,312 | LSDA (C++ EH) |
| `.eh_frame_hdr` / `.eh_frame` | `0x021224 – 0x02d2ac` | 49,288 | DWARF CFI |
| `.text` | `0x02d2ac – 0x1b1bbc` | 1,591,568 | code |
| `.plt` | `0x1b1bc0 – 0x1b2160` | 1,440 | 88 PLT stubs |
| `.data.rel.ro` | `0x1b6160 – 0x1ba5f0` | 17,552 | **`JNINativeMethod[22]` table + encrypted root-path pointer table** |
| `.got` / `.got.plt` | `0x1ba7f0 – 0x1bc2b8` | 6,856 | |
| `.data` / `.bss` | `0x1c02b8 – 0x1c2f38` | 11,392 | global crypto/base64 context @ `0x1c0320` |

### 1.2 Dynamic imports that matter

| Import | Call sites | Purpose |
|---|---|---|
| `access` | 1 (`0x13bac4`, in `func#169`) | **root detection** |
| `clock` | 1 (`0x114ff0`, in `func#98`) | **timing / anti-debug** |
| `memcpy`, `memset`, `strlen`, `strcpy` | many | buffer handling around AES |
| `inflate`, `inflateInit_`, `inflateEnd` | `func#67` | gzip response bodies (OkHttp) |
| `__open_2`, `__read_chk`, `fopen` | `func#200`, `func#225` | **reading `/proc/self/maps`** |
| `dl_iterate_phdr` | `func#1074` | ⚠️ *unwinder code, **not** a detection routine* |
| `syscall` | `func#746` (2 sites) | ⚠️ *libc++ `pthread_condvar` internals, **not** direct-syscall anti-debug* |

> Two of the classic "smells" here are false positives and are explicitly **not** reported as detection (see §3.9).

### 1.3 ABI variants

`lib/{arm64-v8a, x86, x86_64}/libtopfollow.so` are the **same source, same obfuscator pass**:

| | arm64-v8a | x86_64 |
|---|---|---|
| size | 1,805,400 | 1,408,192 |
| functions | 1,090 | 1,080 |
| exports | `JNI_OnLoad` only | `JNI_OnLoad` only |
| XOR-0x5A root-path table | ✔ | ✔ (`0x12640`) |
| identical Base64 strings | ✔ | ✔ |
| AES S-box / LibTomCrypt | ✔ | ✔ (`0xdb80`) |

Anything patched must be patched in **all three**.

---

## 2. JNI surface (how Java reaches the native code)

### 2.1 Registration is fully dynamic

`JNI_OnLoad` (`0x3e1d4`) does `GetEnv` → `FindClass("com/nivaroid/topfollow/helper/q")` → `RegisterNatives(env, cls, table, 22)`.
No `Java_com_nivaroid_…` symbol ever appears in the file — that is why the library looks symbol-free.

### 2.2 The 22 natives → Java method map

Java side: `Lcom/nivaroid/topfollow/helper/q;` — public methods `a`…`v` each delegate to a `private static native` method whose name is an **obfuscated hex slug** (`x00105e9b`, `x0011a4c2`, …). That is R8 output; the slug is meaningless.

| # | Native (Java slug) | Java signature | Native impl | Reconstructed purpose |
|---|---|---|---|---|
| 1 | `x0012f5b7` | `()Ljava/lang/String;` | `func#56` @ `0x435b8` | register device / bootstrap |
| 2 | `x0011e28b` | `(String)String` | `func#57` @ `0x4f078` | encrypt-or-sign a payload |
| 3 | `x0014e2e9` | `()String` | `func#58` @ `0x76508` | constant/endpoint fetch |
| 4 | `x00105e9b` | `(String)String` | `func#59` @ `0x7f82c` | string transform |
| 5 | `x00113f7a` | `()String` | **`func#60` @ `0x81c58`** | **environment integrity (44,957 insns)** |
| 6 | `x0010e27f` | `()String` | `func#61` @ `0xadacc` | device/session id |
| 7 | `x0014b4f3` | `(String)String` | `func#62` | decode |
| 8 | `x0016d3b9` | `()String` | `func#63` @ `0xc67a4` | constant |
| 9 | `x0012d3e0` | `(String)String` | `func#64` @ `0xcbeac` | **`Build.*` device fingerprint** |
| 10 | `x00126f7c` | `(Z, String)Retrofit` | `func#65` | build Retrofit client |
| 11 | `x0018d3f7` | `(I)Retrofit` | `func#66` | build Retrofit client (variant) |
| 12 | `x0014c1f9` | `(Response)String` | `func#67` @ `0xe01e4` | **response processing: gunzip + cert pin + AES** |
| 13 | `x0011f42b` | `()String` | `func#70` | OkHttp client factory |
| 14 | `x0015b1e9` | `(JsonObject,String,String)V` | `func#71` | **`CertificatePinner$Builder`** |
| 15 | `x00135e2a` | `(JsonObject,InstagramAccount,String)V` | `func#72` | **`certificatePinner(...)`** |
| 16 | `x00120b1e` | `(JsonObject,String)V` | `func#73` @ `0x103ad8` | **APK signature → `MessageDigest("SHA-256")`** |
| 17 | `x0011f1a2` | `(Order)String` | `func#87` | order signing |
| 18 | `x0012e5a1` | `(JsonObject)V` | `func#97` @ `0x113cd0` | **`Settings$Secure.ANDROID_ID`** |
| 19 | `x0015a3b7` | `(JsonObject,InstagramAccount,Order)V` | `func#152` | account/order binding |
| 20 | `x0015e49c` | `(Response,Order,InstagramAccount)String` | `func#154` | **root check + order finalisation** |
| 21 | `x0017b62c` | `(String,String,String)String` | `func#156` | 3-arg token/sign |
| 22 | `x0011a4c2` | `()J` | `func#166` @ `0x13a358` | timestamp (`order_stamp2`) |

Full raw table: `work/analysis/jni_natives.txt`.

### 2.3 JNI vtable pressure (evidence of heavy reflection)

| JNI function | call sites |
|---|---|
| `GetStringUTFChars` | 238 |
| `NewStringUTF` | 221 |
| `GetMethodID` | 154 |
| `CallObjectMethod` / `CallVoidMethod` (reflection) | 100 / 96 |
| `FindClass` | ~120 |
| `RegisterNatives` | 2 |

The library drives almost all of its logic **through Java reflection** (`PackageManager`, `Settings$Secure`, `Build`, `MessageDigest`, `okhttp3.*`, `retrofit2.*`, `com.google.gson.*`), which is itself an anti-static-analysis measure: the interesting class/method names never appear as native calls.

### 2.4 Server-provided key material (important)

`DeviceModel` (Room entity, table `MyDatabase`) carries the live crypto state:

```java
class DeviceModel {
    int    id, coin, gem, status, hash_type;
    String token;
    String fcm_token;
    String nonce;       // <-- per-session
    String hash_key;    // <-- per-device, server-issued
}
```

The native code calls `getHash_key()`, `getHash_type()`, `getNonce()`, `getToken()` via JNI (strings `setHash_key @0x15555`, `setNonce @0x15c9f`, `setHash_type @0x16f82`, `hash_key @0x168ab`, `hash_type @0x1679a`, `"nonce" @0x15a42`).

➡ **Two distinct AES key paths exist:** a *server-issued* `hash_key` (used for request signing), and a *hardcoded* key/IV (see §4.2). Both are real; don't conflate them.

---

## 3. Obfuscation techniques

Eleven distinct techniques, quantified. Raw numbers: `work/analysis/obf_report.txt`.

### 3.1 Symbol stripping + dynamic `RegisterNatives`
Only `JNI_OnLoad` is exported. All 22 entry points are resolved at runtime from a relocated `.data.rel.ro` table. Standard IDA/Ghidra "JNI export" heuristics find nothing.

### 3.2 Control-flow flattening (CFF) — the dominant technique
The top 12 functions contain **200,978 of 395,331 instructions = 50.8 % of the entire library**, and **each has exactly one `ret`**:

| Function | Address | Instructions | Branches | `mov`-immediate | `ret` |
|---|---|---|---|---|---|
| `func#60` | `0x081c58` | **44,957** | 5,454 | 12,476 | 1 |
| `func#57` | `0x04f078` | 40,228 | 4,912 | 11,204 | 1 |
| `func#67` | `0x0e01e4` | 29,407 | 3,576 | 8,232 | 1 |
| `func#61` | `0x0adacc` | 18,252 | 2,218 | 5,096 | 1 |
| `func#56` | `0x0435b8` | 11,952 | 1,462 | 3,320 | 1 |
| `func#226` | `0x159c10` | 11,502 | 1,402 | 3,240 | 1 |
| `func#58` | `0x076508` | 9,417 | 1,148 | 2,616 | 1 |
| `func#64` | `0x0cbeac` | 8,703 | 1,062 | 2,432 | 1 |
| `func#66` | `0x0d80e8` | 8,255 | 1,006 | 2,312 | 1 |
| `func#63` | `0x0c67a4` | 5,570 | 680 | 1,548 | 1 |
| `func#154` | `0x12a068` | 5,244 | 640 | 1,472 | 1 |
| `func#73` | `0x103ad8` | 4,513 | 552 | 1,264 | 1 |

Signature: a **dispatcher block** at the function head compares a state variable against a large immediate and `b.eq`/`b.ne` fans out to basic blocks that each end by re-writing the state variable and branching back. Classic OLLVM `-fla`.

**Deflattening recipe that works here:** the state variable is always kept in a callee-saved register (`w19`–`w28`) and each real block ends with `mov wN, #imm32; b <dispatcher>`. Collecting `(imm32 → block)` pairs recovers the original CFG exactly. In `func#60` that yields ~2,700 original blocks.

### 3.3 Constant blinding
Every literal is split into `movz`/`movk` pairs and combined with an arithmetic identity. Example from `func#193`:

```asm
0x141988: sub  w10, w8, #1
0x14198c: mul  w8,  w10, w8          ; w8 = n*(n-1)
0x141990: eor  w10, w8, #0xfffffffe
0x14199c: tst  w10, w8               ; ALWAYS true (n*(n-1) is even)
0x1419a8: cset w8,  eq               ; opaque predicate
```

`func#15` (`AES_set_encrypt_key` wrapper) opens with **seven** consecutive `mov`/`movk` pairs building junk 32-bit selectors before any real work.

### 3.4 Opaque predicates
Always of the form `(n * (n-1)) & 0xFFFFFFFE == 0` (product of consecutive ints is even ⇒ always true) or `cmp w9, #0xa; cset w9, lt` chains that never diverge. They double the apparent branch count without changing semantics. Present in essentially every function >1,000 instructions.

### 3.5 Mixed-Boolean-Arithmetic (MBA) — the XOR decryptor
The single-byte XOR used to decrypt strings is never emitted as `eor`. It is emitted as the 3-instruction MBA identity `a ^ b == (a & ~b) | (~a & b)`:

```asm
; func#170 @ 0x13be44   — string decryptor core
bic  w9, w23, w8        ; w9 = key & ~ct
bic  w8, w8,  w23       ; w8 = ct  & ~key
orr  w1, w9,  w8        ; w1 = key ^ ct          <-- the XOR
```

The key byte is **inlined as an immediate at each call site**, so there is no single "key" to patch — you must recover it per blob.

### 3.6 Single-byte XOR string encryption
See §5 for the full decoded corpus. Three keys in use: `0x5A`, `0x37`, `0x1B` (+ `0x20` on the Base64 alphabet).

### 3.7 Multi-layer Base64 string encoding
Strings are Base64-encoded **2–5 times** so that a single decode pass does not reveal them:

```
'WVVoU01HTklUVFpNZVRsd1RHMXNkV016VW1oYU0wcG9ZbE0xYW1JeU1IWlpXRUp3VEROWmVVeDNQVDA9'
  → 'YUhSMGNITTZMeTlwTG1sdWMzUmhaM0poYlM1amIyMHZZWEJwTDNZeUx3PT0='
  → 'aHR0cHM6Ly9pLmluc3RhZ3JhbS5jb20vYXBpL3YyLw=='
  → 'https://i.instagram.com/api/v2/'          (4 layers)
```

### 3.8 Dead code / unreachable blocks
`func#169` (root check) contains an **infinite-loop dead branch** placed after the real `return`, inflating size and confusing CFG recovery. `func#1046 @ 0x1adb78` (`fprintf`+`fflush`+`abort`, 313 callers) is the libc++ assertion handler — high fan-in, zero security value; ignore it.

### 3.9 Static libc++ / no external crypto dependency
`libc++_static` is linked in, so 900+ of the 1,090 functions are STL/unwinder noise (`std::__ndk1::…`, `_Unwind_*`, `__cxa_*`). The obfuscator flattened some of these too, which is why they look suspicious. **Do not report `dl_iterate_phdr` (`func#1074`, unwinder) or `syscall` (`func#746`, `pthread_condvar`) as anti-debug** — verified false positives.

### 3.10 R8/ProGuard name mangling (Java layer)
`helper/q`, `helper/T`, `helper/a0`, `application/G`, `db/MyDatabase` — plus `x0011a4c2`-style native names.

### 3.11 Certificate pinning as tamper detection
Not obfuscation per se, but it blocks the most common dynamic-analysis tool (MITM proxy). See §3.7-detection below and §6.

---

## 4. Encryption — complete inventory

### 4.1 AES: it is **LibTomCrypt**, positively identified

Four independent fingerprints match LibTomCrypt's `rijndael` implementation bit-for-bit:

| Artifact | Address | Value | Verdict |
|---|---|---|---|
| Te0 (encrypt T-table) | `0x118b0` | `a5 63 63 c6 …` = `0xc66363a5` | ✔ |
| Te1 / Te2 / Te3 | `0x11cb0` / `0x120b0` / `0x124b0` | rotations of Te0 | ✔ |
| S-box | `0x128b0` | `63 7c 77 7b f2 6b 6f c5 …` | ✔ |
| Td0 (decrypt T-table) | `0x129b0` | `0x51f4a750` | ✔ |
| Td1 / Td2 / Td3 | `0x12db0` / `0x131b0` / `0x135b0`-region | rotations | ✔ |
| RS-box | `0x139b0` | | ✔ |
| **`Rcon`** | **`0x135b0`** | `5150a7f4 7e536541 1ac3a417 3a965e27 3bcb6bab 1ff1459d acab58fa 4b9303e3 2055fa30 adf66d76 889176cc` | ✔ **LibTomCrypt-specific** (OpenSSL uses `01 02 04 08 10 20 40 80 1b 36`) |
| `setup_log` (GF(2⁸) log) | `0x13b10` | `01 02 04 08 10 20 40 80 1b 36 6c d8 ab 4d 9a 2f 5e bc 63 c6 97 35 6a d4 b3 7d fa ef c5 91` | ✔ **LibTomCrypt-specific** |
| `setup_alog` | `0x13b30`, `0x13f30`, `0x14330`, `0x14730` | | ✔ |

Dead data (no xref, ignore): 1,008-byte blob `0x14770–0x14b30`, `Te4 @0x145b0`, `Td4 @0x146b0`.

**Function-level AES map:**

| Function | Address | Size | Role | Referenced tables |
|---|---|---|---|---|
| `func#10` | `0x02dc00` | 3,988 | `rijndael_ecb_encrypt` | Te0-Te3, S-box |
| `func#11` | `0x02eb94` | 4,664 | `rijndael_ecb_decrypt` | Td0-Td3, Rcon |
| `func#12` | `0x02fdcc` | 4,428 | encrypt variant (key-sched aware) | Te0-Te3, S-box, `setup_alog` |
| `func#13` | `0x030f18` | 4,672 | decrypt variant | Td0-Td3, Rcon, `setup_alog` |
| **`func#14`** | **`0x032158`** | **8,908** | **`rijndael_setup` (key expansion)** — supports **10/12/14 rounds** (`cmp w8,#0xa`, `mov w9,#0xc`, `mov w8,#0xe` ⇒ AES-128/192/256) | S-box, `setup_log`, `setup_alog`×4 |
| `func#15` | `0x034424` | 4,340 | set-encrypt-key wrapper → calls `#9`, `#12`; 6× `memcpy` | |
| `func#16` | `0x035518` | 2,112 | set-decrypt-key wrapper → calls `#9`, `#12`, `#13`; 4× `memcpy` | |
| `func#17` | `0x035d58` | — | `strlen`-based buffer helper | |
| **`func#30`** | **`0x038fa4`** | **4,508** | **AES-CBC encrypt (high-level)** — callers `#56 #57 #59 #60 #61 #63 #67` | uses `memset`,`strcpy`,`#14`,`#15` |
| **`func#36`** | **`0x03a838`** | **1,708** | **AES-CBC decrypt (high-level)** — caller `#252` | `#14`,`#16`, 2× `memcpy` |
| **`func#85`** | **`0x10c470`** | **6,556** | **AES encrypt + envelope build** — callers `#54 #57 #58 #60 #62 #65 #67 #154 #226` (9 sites) | `#14`,`#15`,`#23`,`#35`,`#43`,`#76`,`#81` |
| **`func#94`** | **`0x110b70`** | **9,140** | **AES decrypt + envelope parse** — callers `#55 #56 #153` | `#14`,`#16`,`#23`,`#37`,`#43`,`#76`,`#81` |
| `func#176` | `0x13d098` | 612 | crypto-object constructor → `#179 #180 #181 #182` | |
| `func#177` | `0x13d2fc` | 824 | cipher init → `func#191` (4,672 B, the real core) | |
| `func#178` | `0x13d634` | 352 | cipher finish → `#181`, `#192` | |
| `func#193` | `0x14193c` | 1,824 | `copy(src,len,dst)` key/IV installer (obfuscated `memcpy`) | |

**Call graph (AES):**

```
JNI m2/m5/m9/m12/m16/m20  ─┐
                           ├─> func#30 (AES-CBC enc) ──> func#15 ──> func#12 ──> func#10 (Te tables)
func#54/#55 (helpers) ─────┤                        └─> func#14 (key expansion, Rcon)
                           └─> func#85 (enc+envelope) ─> func#15, func#14
func#55/#56/#153 ───────────> func#94 (dec+envelope) ─> func#16 ──> func#13 ──> func#11 (Td tables)
func#252 ────────────────────> func#36 (AES-CBC dec) ──> func#16, func#14
func#157 ────────────────────> func#176/#177/#178 ────> func#191 (4,672 B cipher core)
```

### 4.2 ★ Hardcoded AES-256 key and IV

`func#157 @ 0x131d58` (7,192 B, 1,798 insns; called by JNI `func#57` and `func#64`) begins by installing a **fixed 32-byte key and 16-byte IV**:

```asm
; ---- func#157 prologue (0x131d58) ----
0x00131d58: sub   sp, sp, #0x120
0x00131d78: mrs   x19, tpidr_el0            ; stack canary
0x00131d7c: mov   x20, x8                   ; x8 = sret -> crypto object
0x00131d84: mov   x21, x0                   ; x0 = JNIEnv*/input
0x00131d88: adrp  x0, #0x17000
0x00131d8c: add   x0, x0, #0x428            ; x0 = &KEY_CT   (0x17428)
0x00131d94: sub   x8, x29, #0x28            ; x8 = &obj.keybuf   (sret)
0x00131d98: mov   w1, #0x20                 ; len = 32   ==> AES-256
0x00131d9c: bl    func#193                  ; copy(KEY_CT, 32, &obj.keybuf)

0x00131da0: adrp  x0, #0x17000
0x00131da4: add   x0, x0, #0x448            ; x0 = &IV_CT    (0x17448)
0x00131da8: sub   x8, x29, #0x40            ; x8 = &obj.ivbuf
0x00131dac: mov   w1, #0x10                 ; len = 16   ==> 128-bit IV
0x00131db0: bl    func#193                  ; copy(IV_CT, 16, &obj.ivbuf)

0x00131f88: bl    func#176                  ; crypto object ctor
0x00132e00: bl    func#177                  ; cipher init  -> func#191 core
0x00132fec: bl    func#178                  ; cipher finish
0x0013333c: bl    func#178
0x001336e8: bl    func#178
```

`func#193` is a hand-rolled, opaque-predicate-laden `memcpy(src=x0, len=x1, dst=x8)` — no transformation is applied to the bytes.

**The raw material:**

```
.rodata:0x17428  KEY (32 bytes, AES-256)
  1b 2e 63 6b 13 22 0c 34 08 09 38 1c 2a 2a 0c 6a
  0f 22 14 1c 3e 0f 09 34 2a 36 0e 0d 6f 15 14 1b

.rodata:0x17448  IV (16 bytes)
  0d 17 0c 1f 2d 0c 1d 6a 68 3f 1d 1c 36 0c 37 08
```

**Encoding status — honest result:** these bytes are **not** a single-byte XOR of printable ASCII (all 256 keys swept → no clean result), **not** additive/subtractive, **not** positional `k+i` / `k*i`, and **not** Base64/hex text. They are consumed *verbatim* by `func#193`, so they are **raw binary key material embedded in the file**.

That is the security-relevant conclusion: **the AES-256 key and IV are static, identical on every install, and shipped inside the APK.** Consequences:

* anyone who extracts 48 bytes from `.rodata:0x17428` can decrypt everything this path protects;
* the IV is fixed ⇒ CBC mode leaks plaintext equality across messages and is trivially replayable;
* a patch at `0x17428`/`0x17448` (or an Xposed hook on `func#193`) redirects the whole scheme.

**Derived digests of the raw material** (for correlation with captured traffic):

```
sha256(KEY || IV) region  : (see below, per-buffer)
sha256(KEY[0:32])         : 555477f4526e697739ea22acf4d1b6f61ca73727c626188f64d683213829b052
md5   (KEY[0:32])         : d464aa635c01b79e60951e6dc6b295ff
sha256(IV[0:16])          : dd0cfd9d0c1c5d187568f52fee99ee60ce23dd8fa3aefdcc6e36811ada390a62
```

**Second candidate key blob** — `.rodata:0x17307`, 32 high-entropy bytes, referenced by `func#86 @0x10de0c` (94 insns, a getter) and consumed by `func#54` / `func#55` (the AES-enc/dec helpers that call `func#85`/`func#94`):

```
0x17307: 90 fe fa c8 da dd be 95 f9 b4 17 4f 55 7c 45 32
         f0 c5 8e f5 fd be ac 9d 85 92 71 48 61 41 6b 3f
sha256(blob) = af8b3668b3c8deb5834394c1321622192b3ac5163398d6b82fdec57266b94477
```

Also no single-byte XOR decode. Treat as a **second static 256-bit key** (used on the `func#54/#55` encrypt/decrypt path).

### 4.3 SHA-256 — LibTomCrypt, standard constants

| Artifact | Address | Verified value |
|---|---|---|
| `H0[0..7]` | `0x17220` | `6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19` — **exact standard, LE dwords** |
| `K[0..63]` | `0x174c4 – 0x175c4` | `428a2f98 71374491 b5c0fbcf e9b5dba5 …` … `K[63] = c67178f2` — **exact standard** |
| JNI string `SHA-256` | `0x16645` | alongside `java/security/MessageDigest @0x16629` |

**Native SHA-256 functions:**

| Function | Address | Size | Role | Callers |
|---|---|---|---|---|
| `func#212` | `0x1509cc` | 5,276 | **`sha256_compress`** (only referrer of `K`) | `#209`, `#210` |
| `func#214` | `0x153628` | — | compress tail (refs `K[63]`) | |
| `func#209` | `0x14f06c` | — | `sha256_init` / `update` | `#204`, `#208` |
| `func#210` | `0x14f6e4` | — | `sha256_done` | `#204`, `#208` |
| `func#208` | `0x14e8fc` | 1,904 | one-shot digest helper | `#204` |
| `func#204` | `0x148bf4` | **16,312** | **SHA-256 pipeline** (JNI m5 wrapper region) | `#60`, `#61` |
| `func#211` | `0x1500bc` | 2,320 | hex/base64 formatting of digest | `#204` |
| `func#245` | `0x16bbdc` | 2,076 | **pin hash SHA-256** (holds the cert-pin blob `0x15084`) | `#226` |

**Java-side SHA-256:** `func#73` (JNI m16) and `func#226` both do
`FindClass("java/security/MessageDigest")` → `GetInstance("SHA-256")` → `digest(byte[])`.
So SHA-256 is available **twice** — native LibTomCrypt *and* JNI-upcalled `MessageDigest`. The JNI path is used for the **APK signature digest** (see §3-detection 3.6) and the **certificate pin**.

No MD5, no SHA-1, no SHA-512 constants exist anywhere in the binary (searched both endiannesses).

### 4.4 Base64

| Item | Address | Detail |
|---|---|---|
| Alphabet (canonical) | `0x1501a` | `ABC…XYZabc…xyz0123456789+/` — **standard** |
| Alphabet (obfuscated copy) | `0x17327` | stored **XOR 0x20**; recovered by `func#170` |
| Global Base64 context | `0x1c0320` (`.data`) | |
| Pointer table | `0x1b6160` (`.data.rel.ro`) | |
| `func#26` | `0x03896c` | 68 B — **alphabet installer**: `add x1,x1,#0x1a → 0x1501a; bl func#17 (strlen); add x19,x19,#0x320 → 0x1c0320` |
| `func#796` | `0x19c864` | 8,144 B — the Base64 encode/decode engine (16 data refs into `.rodata`) |
| `func#17` | `0x035f58` | `strlen`-based setup helper |

Note the alphabet at `0x1501a` is **canonical** — the "custom alphabet" hypothesis from the raw dump at `0x1732c` was a mis-read of the XOR-0x20 storage; after decoding it is the standard alphabet. Base64 here is **encoding, not encryption**.

### 4.5 HMAC / request signing (`hash_key`, `nonce`, `sign`)

Plaintext field names in `.rodata` prove a signing protocol:

| String | Address |
|---|---|
| `hash_key` | `0x168ab` |
| `"hash_key"` (JSON literal) | `0x16665` |
| `hash_type` | `0x1679a` |
| `"hash_type"` | `0x16c20` |
| `nonce` | `0x151f5` |
| `"nonce"` | `0x15a42` |
| `sign` | `0x14ecf` |
| `digest` | `0x14b88` |
| `signatures` | `0x14e80` |
| `order_stamp`, `order_stamp2`, `order_stamp3` | `0x14e96`, `0x1648d`, … |
| `token`, `fcm_token` | `0x16f5a`, `0x159d5` |
| `family_device_id`, `getDevice`, `addDevice` | `0x1647c`, `0x16472`, `0x16f8f` |

Flow: server issues `hash_key` + `nonce` + `hash_type` → stored in `DeviceModel` (Room) → native reads them by JNI reflection → `func#85`/`func#94` AES-wrap the request → SHA-256 over `order_id || order_stamp || nonce || …` produces `sign` / `digest` → sent to Instagram endpoints and to the app's own backend.

`hash_type` is an **integer selector** (the `x0`, `x2`, `x4`, `x5`, `x10` strings at `0x167a9`-region are the enum names) — i.e. the server can rotate which digest/AES variant the client must use. That is the one genuinely non-static part of the scheme.

### 4.6 Endpoints recovered

```
https://i.instagram.com/api/v2/            (4-layer base64 @0x159ec)
https://www.instagram.com/                 (2-layer base64 @0x15c02)
https://www.instagram.com/graphql/query    (3-layer base64 @0x15de3)
https://                                   (4-layer base64 @0x14eae)
create_note/v2/                            (3-layer base64 @0x14bf4)
seen/                                      (3-layer base64 @0x16b60)
/save/                                     (2-layer base64 @0x14de8)
```

### 4.7 What is **not** present
No MD5, no SHA-1, no SHA-512, no RC4, no ChaCha, no RSA/ECC/DSA constants, no HMAC ipad/opad bytes (`0x36`/`0x5c` block patterns) — the "HMAC" here is a hand-rolled SHA-256 concatenation, not RFC 2104 HMAC.

---

## 5. Encrypted-string corpus (fully decoded)

### 5.1 XOR-encrypted blobs

| Blob | Len | Key | Owner | Decoded |
|---|---|---|---|---|
| `0x1746f` | 85 | **0x5A** | **`func#200`** (anti-hook) | `U` + `/proc/self/maps` `xposed` `lsposed` `edxposed` `riru` `substrate` `libcso_substrate` `libbridge.so` `zygisk` + `Z` — 9 tokens **packed with no separators**, framed by literal `U`/`Z` guard bytes; sliced by offset (see below) |
| `0x17365` | 41 | **0x37** | **`func#99`** (anti-Frida) | `gum-js-loop` `libfrida-gadget` `re.frida.server` — 3 tokens **packed with no separators**, no guards, sliced by offset |
| `0x1738e` | 25 | 0x5A | `func#169` root #1 | `/system/app/Superuser.apk` |
| `0x173a7` | 8 | 0x5A | root #2 | `/sbin/su` |
| `0x173af` | 14 | 0x5A | root #3 | `/system/bin/su` |
| `0x173bd` | 15 | 0x5A | root #4 | `/system/xbin/su` |
| `0x173cc` | 19 | 0x5A | root #5 | `/data/local/xbin/su` |
| `0x173df` | 18 | 0x5A | root #6 | `/data/local/bin/su` |
| `0x173f1` | 18 | 0x5A | root #7 | `/system/sd/xbin/su` |
| `0x17403` | 23 | 0x5A | root #8 | `/system/bin/failsafe/su` |
| `0x1741a` | 14 | 0x5A | root #9 | `/data/local/su` |
| `0x17327` | 65 | 0x20 | `func#26` | Base64 alphabet (canonical) |
| `0x1742b` | 68 | 0x1B | `func#157`/`func#158` | **not single-byte-XOR decodable** — key sweep failed for all 256 keys and for positional variants. Reported as *encrypted, key not recovered*. (Earlier note claiming storage paths here was **wrong** and is retracted.) |

The 9 root paths are **not** inline in `.rodata` — they are reached through a `(const char* ptr, size_t len)` table in `.data.rel.ro @ 0x1b63a8` (9 entries, resolved via LIEF relocations), which is why naive string search misses them.

**Token slicing (important detail).** Neither packed blob contains a delimiter byte — `0x1A` does **not** appear in either. The scanner functions instead hold one `adrp`/`add` per token, i.e. they index the *decrypted* buffer by hard-coded offset. The exact ref → token map, recovered from `funcmap.json` data refs:

`func#200` — hook blob `0x1746f`, XOR `0x5A`, `U`(0x55)…`Z`(0x5A) guards:

| data ref | index into decoded blob | token | len |
|---|---|---|---|
| `0x17470` | 1 | `/proc/self/maps` | 15 |
| `0x1747f` | 16 | `xposed` | 6 |
| `0x17485` | 22 | `lsposed` | 7 |
| `0x1748c` | 29 | `edxposed` | 8 |
| `0x17494` | 37 | `riru` | 4 |
| `0x17498` | 41 | `substrate` | 9 |
| `0x174a1` | 50 | `libcso_substrate` | 16 |
| `0x174b1` | 66 | `libbridge.so` | 12 |
| `0x174bd` | 78 | `zygisk` | 6 |

`func#99` — Frida blob `0x17365`, XOR `0x37`, no guards:

| data ref | index | token | len |
|---|---|---|---|
| `0x17365` | 0 | `gum-js-loop` | 11 |
| `0x17370` | 11 | `libfrida-gadget` | 15 |
| `0x1737f` | 26 | `re.frida.server` | 15 |

Note the blob starts at `0x17365`, not `0x17366` — the leading `g` sits one byte earlier and is easy to clip off when reading the region blindly.


### 5.2 Base64-encoded blobs (nested depth noted)

| Address | Layers | Decoded |
|---|---|---|
| `0x14bf4` | 3 | `create_note/v2/` |
| `0x14de8` | 2 | `/save/` |
| `0x14eae` | 4 | `https://` |
| **`0x15084`** | **2** | **`d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e`** ← the certificate pin |
| `0x15541` | 1 | `libbridge.so` |
| `0x156df` | 1 | `riru` |
| `0x156e8` | 1 | `libcso_substrate` |
| `0x159ec` | 3 | `https://i.instagram.com/api/v2/` |
| `0x15be1` | 1 | `frida` |
| `0x15c02` | 2 | `https://www.instagram.com/` |
| `0x15db5` | 1 | `/proc/self/maps` |
| `0x15dd4` | 1 | `substrate` |
| `0x15de3` | 3 | `https://www.instagram.com/graphql/query` |
| `0x1607f` | 1 | `re.frida.server` |
| `0x161eb` | 1 | `gum-js-loop` |
| `0x16204` | 1 | `edxposed` |
| `0x16336` | 1 | `rwxp` |
| `0x167a9` | 1 | `lsposed` |
| `0x16b60` | 3 | `seen/` |
| `0x16b75` | 1 | `libart.so (deleted)` |
| `0x16c11` | 1 | `xposed` |
| `0x16d97` | 1 | `libfrida-gadget` |
| `0x16f60` | 1 | `ygsik` (anagram of *kyigi* / *zygisk*-adjacent marker) |
| `0x16f69` | 1 | `libc.so (deleted)` |
| `0x1606a` | 3 | `HbF0Nh5lp` (opaque app token) |

Full corpus: `work/analysis/all_decoded_strings.txt`.

---

## 6. Detection mechanisms

Every routine below is **attributed by data-reference inversion** (`adrp`/`add` targets → owning function), not by string proximity. Machine-readable version: `work/analysis/final_detection_map.txt`.

### 6.1 Anti-hook framework scan — `func#200 @ 0x145f88` (8,540 B, 2,135 insns)

Called by `func#57`, `func#61` (both JNI entry points).
Touches **9 distinct offsets inside the XOR-0x5A blob at `0x1746f`** — exactly one per token:

```
refs: 0x17470 0x1747f 0x17485 0x1748c 0x17494 0x17498 0x174a1 0x174b1 0x174bd
      maps    xposed  lsposed edxposed riru   substrate libcso  libbridge zygisk
```

Decrypted blob (85 bytes, XOR `0x5A`, `U`…`Z` guard frame):
```
U/proc/self/mapsxposedlsposededxposedrirusubstratelibcso_substratelibbridge.sozygiskZ
```

Mechanism: decrypt the blob with the MBA XOR (`bic/bic/orr`, key `0x5A` inlined at the call site), then `fopen("/proc/self/maps","r")` and `fgets` line-by-line. Each of the 8 framework tokens is addressed **by its own `adrp`/`add`** — there are no delimiters in the blob, so the lengths are implicit in the gap between consecutive refs. Uses `__open_2` / `__read_chk` (FORTIFY-hardened variants). Any hit ⇒ the environment is considered compromised.

### 6.2 Anti-Frida — `func#99 @ 0x115770` (6,752 B, 1,688 insns)

Called by `func#56`, `func#57`, **and `func#226` (the cert-pinner)** — i.e. Frida is checked right before TLS pins are applied.
Refs `0x17365`, `0x17370`, `0x1737f` inside the XOR-0x37 blob at `0x17365` (41 bytes, no guard bytes):

```
gum-js-loop          @ idx 0   len 11   (Frida's JS event-loop thread name)
libfrida-gadget      @ idx 11  len 15   (embedded gadget .so)
re.frida.server      @ idx 26  len 15   (frida-server process/package name)
```

`func#162 @ 0x136cb8` (callers `#57`, `#65`) additionally Base64-decodes the plaintext-B64 copies `frida` (`0x15be1`), `libfrida-gadget` (`0x16d97`), `re.frida.server` (`0x1607f`), `gum-js-loop` (`0x161eb`) and `/proc/self/maps` (`0x15db5`) — a **second, redundant** Frida path using a *different* encoding of the same tokens. Both must be neutralised.

> Note: there is **no** plaintext `frida` string anywhere in the file. The only `Frid…` match in the whole binary is `Friday` at `0x15e68` (libc++ `time_put` weekday table). Anyone grepping for `frida` finds nothing.

### 6.3 Root detection — `func#169 @ 0x13ba30` (576 B, 144 insns)

Called by `func#154` (JNI m20). The **only** caller of the `access@PLT` stub (`0x13bac4`).

```c
// reconstructed
bool is_rooted(void) {
    static const struct { const char *p; size_t n; } T[9] = /* .data.rel.ro:0x1b63a8 */;
    for (int i = 0; i < 9; i++) {
        char buf[64];
        xor_decode(T[i].p, T[i].n, 0x5A, buf);      // MBA bic/bic/orr, key inlined
        if (access(buf, F_OK /*0*/) == 0)
            return true;                            // rooted
    }
    return false;
}
```

The nine paths are the canonical `su` locations listed in §5.1. No `su` invocation, no `which`, no Magisk-manager package check — filesystem presence only.

### 6.4 `/proc/self/maps` integrity — `func#225 @ 0x157f38` (7,384 B, 1,846 insns)

Called by `func#67` (JNI m12, the response processor). References **four** independent Base64 markers:

| Address | Decoded | What it detects |
|---|---|---|
| `0x15db5` | `/proc/self/maps` | the file to scan |
| `0x16336` | `rwxp` | **writable+executable mappings** ⇒ runtime code injection / JIT-based hookers |
| `0x16b75` | `libart.so (deleted)` | ART replaced/patched in place |
| `0x16f69` | `libc.so (deleted)` | libc replaced (typical of Substrate/Riru preload) |

`(deleted)` in a maps path means the inode was unlinked while mapped — the signature of an in-place patched system library.

### 6.5 APK signature / installer verification — `func#73 @ 0x103ad8` (18,052 B, 4,513 insns) & `func#226 @ 0x159c10` (46,008 B, 11,502 insns)

Both reference the identical 7-string cluster:

| Address | String |
|---|---|
| `0x157df` | `getPackageManager` |
| `0x15b8b` | `getPackageInfo` |
| `0x15bb0` | `(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;` |
| `0x15eda` | `(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;` |
| `0x15f83` | `[Landroid/content/pm/Signature;` |
| `0x15fa3` | `toByteArray` |
| `0x14e80` | `signatures` |
| `0x16629` / `0x16645` | `java/security/MessageDigest` / `SHA-256` |

Reconstructed logic:

```java
PackageInfo pi = ctx.getPackageManager()
                    .getPackageInfo(ctx.getPackageName(), GET_SIGNATURES);
for (Signature s : pi.signatures) {
    byte[] d = MessageDigest.getInstance("SHA-256").digest(s.toByteArray());
    // compare d against the pinned value
}
```

The pinned value is the **triple-Base64 blob at `0x15084`**:

```
d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e
```

`func#245 @ 0x16bbdc` (2,076 B) is the dedicated pin-hash routine; it is called **only** by `func#226`. A re-signed / repackaged APK therefore fails, and `func#226` also drives the AES layer (`func#85`) and the timing check (`func#98`), so failure poisons the crypto path rather than throwing a clean error.

### 6.6 TLS certificate pinning — `func#253 @ 0x172460`, `func#254 @ 0x173c40`, `func#71/#72`

| Address | String |
|---|---|
| `0x15113` | `okhttp3/CertificatePinner$Builder` |
| `0x1536c` | `(Ljava/lang/String;[Ljava/lang/String;)Lokhttp3/CertificatePinner$Builder;` |
| `0x16240` | `(Lokhttp3/CertificatePinner;)Lokhttp3/OkHttpClient$Builder;` |
| `0x1649e` | `certificatePinner` |
| `0x16a7e` | `()Lokhttp3/CertificatePinner;` |
| `0x14ee5` | `nonce` (bound into the pinned client) |

Chain: `func#71`/`func#72` (JNI m14/m15) → `func#253` builds `CertificatePinner$Builder`, adds `sha256/d845591e…` for the Instagram hosts → `func#254` installs it on `OkHttpClient$Builder`. `func#70` supplies `()Lokhttp3/OkHttpClient;`.

This defeats Burp/mitmproxy/Charles out of the box; you must hook `CertificatePinner.check` **and** defeat `func#99`'s Frida scan first.

### 6.7 Timing / anti-debug — `func#98 @ 0x114fbc`

The **only** caller of `clock@PLT` (`0x114ff0`). Called by **13 functions**, including every large JNI entry point and `func#226` (cert pinner). Pattern: `t0 = clock(); <work>; t1 = clock(); if (t1 - t0 > threshold) ⇒ traced`.

### 6.8 Device fingerprinting

| Function | Address | Fields read |
|---|---|---|
| `func#64` (JNI m9) | `0x0cbeac` | `Build.*` — `BRAND @0x16c10`, `DEVICE @0x16211`, model/manufacturer family |
| `func#97` | `0x113cd0` | `android/provider/Settings$Secure @0x1643c`, `ANDROID_ID @0x1645d`, `getString @0x16468`, `getDevice`, `family_device_id @0x1647c` |
| `func#152` | `0x12472c` | `fcm_token @0x159d5`, `token` |
| `func#166` (JNI m22) | `0x13a358` | `order_stamp2 @0x1648d` — monotonic time |
| `func#247` | `0x16c564` | `addDevice`, `setHash_key`, `setNonce`, `setHash_type` — writes the server-issued crypto state into `DeviceModel` |

Used to bind the `hash_key`/`nonce` to a device, so credentials cannot be lifted to another handset.

### 6.9 Verified **non**-detections (avoid false positives)

| Function | Symbol | Real purpose |
|---|---|---|
| `func#746 @ 0x196c54` | `syscall` ×2 | libc++ `std::condition_variable` / `pthread_mutex` internals; 57 benign callers |
| `func#1074 @ 0x1ae5a8` | `dl_iterate_phdr` | `.eh_frame` **unwinder** |
| `func#1046 @ 0x1adb78` | `fprintf`+`fflush`+`abort` | libc++ assertion handler; 313 callers |
| `func#67` | `inflate*` | gzip on **network response bodies**, not a hidden payload |

There are **no** emulator-detection strings (no `qemu`, `goldfish`, `nox`, `bluestacks`, `vbox`, `genymotion`), no `ptrace(PTRACE_TRACEME)` self-attach, no `TracerPid` scan, no `ro.debuggable`/`ro.secure` property reads, and no Play Integrity / SafetyNet attestation.

---

## 7. Decompiled / reconstructed source

Faithful C reconstructions of the security-critical routines. Full annotated disassembly (400 K lines, every `adrp/add` resolved to its target and every `bl` to its PLT name) is at `work/analysis/annotated_arm64.txt`.

### 7.1 `JNI_OnLoad`

```c
// 0x3e1d4 — control-flow flattened, constants blinded
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;

    jclass cls = (*env)->FindClass(env, "com/nivaroid/topfollow/helper/q");
    if (!cls) return JNI_ERR;

    // table lives in .data.rel.ro, filled by R_AARCH64_RELATIVE relocs
    static const JNINativeMethod methods[22] = { /* see §2.2 */ };

    if ((*env)->RegisterNatives(env, cls, methods, 22) < 0)
        return JNI_ERR;

    return JNI_VERSION_1_6;
}
```

### 7.2 The MBA XOR string decryptor (`func#170 @ 0x13be44`)

```c
// Emitted per call site; the key is an inlined immediate.
// AArch64 source:
//     bic w9, w23, w8     ; key & ~ct
//     bic w8, w8,  w23    ; ct  & ~key
//     orr w1, w9,  w8     ; == key ^ ct
static inline uint8_t mba_xor(uint8_t ct, uint8_t key) {
    return (uint8_t)((key & (uint8_t)~ct) | (ct & (uint8_t)~key));
}

// Generic blob decoder as used at every site
static void decode_blob(const uint8_t *src, size_t n, uint8_t key, char *dst) {
    for (size_t i = 0; i < n; i++)
        dst[i] = (char)mba_xor(src[i], key);
    dst[n] = '\0';
}
```

### 7.3 Root detection (`func#169 @ 0x13ba30`)

```c
typedef struct { const char *ct; size_t len; } EncStr;

// .data.rel.ro:0x1b63a8 — 9 entries, all XOR 0x5A
static const EncStr ROOT_PATHS[9] = {
    { (const char*)0x1738e, 25 },  // /system/app/Superuser.apk
    { (const char*)0x173a7,  8 },  // /sbin/su
    { (const char*)0x173af, 14 },  // /system/bin/su
    { (const char*)0x173bd, 15 },  // /system/xbin/su
    { (const char*)0x173cc, 19 },  // /data/local/xbin/su
    { (const char*)0x173df, 18 },  // /data/local/bin/su
    { (const char*)0x173f1, 18 },  // /system/sd/xbin/su
    { (const char*)0x17403, 23 },  // /system/bin/failsafe/su
    { (const char*)0x1741a, 14 },  // /data/local/su
};

bool sub_13BA30_isRooted(void) {           // func#169
    char path[64];
    for (int i = 0; i < 9; i++) {
        decode_blob((const uint8_t *)ROOT_PATHS[i].ct,
                    ROOT_PATHS[i].len, 0x5A, path);
        if (access(path, F_OK) == 0)        // PLT access @0x13bac4
            return true;
    }
    return false;
    /* followed by an unreachable infinite loop (dead-code padding) */
}
```

### 7.4 Anti-hook maps scan (`func#200 @ 0x145f88`)

```c
// XOR-0x5A blob @0x1746f, 85 bytes. NO delimiter bytes — tokens are packed and
// addressed individually; the blob is framed by literal 'U' (0x55) and 'Z' (0x5A)
// guard bytes which are skipped, not decoded as data.
static const uint8_t HOOK_BLOB[85] = { /* .rodata:0x1746f */ };

// offset = blob_ref - 0x1746f ; length = next_offset - offset (last token to the 'Z')
static const struct { uint16_t off, len; const char *name; } HOOK_TOKENS[9] = {
    {  1, 15, "/proc/self/maps"   },   // adrp/add -> 0x17470
    { 16,  6, "xposed"            },   //            0x1747f
    { 22,  7, "lsposed"           },   //            0x17485
    { 29,  8, "edxposed"          },   //            0x1748c
    { 37,  4, "riru"              },   //            0x17494
    { 41,  9, "substrate"         },   //            0x17498
    { 50, 16, "libcso_substrate"  },   //            0x174a1
    { 66, 12, "libbridge.so"      },   //            0x174b1
    { 78,  6, "zygisk"            },   //            0x174bd
};

bool sub_145F88_isHooked(void) {           // func#200
    char blob[96];
    decode_blob(HOOK_BLOB, sizeof HOOK_BLOB, 0x5A, blob);   // 'U' … 'Z' guards included

    FILE *f = fopen(&blob[1] /* "/proc/self/maps" */, "r"); // __open_2 / __read_chk
    if (!f) return false;

    char line[512];
    while (fgets(line, sizeof line, f)) {
        for (int i = 1; i < 9; i++) {                       // token 0 is the path itself
            char tok[32];
            memcpy(tok, blob + HOOK_TOKENS[i].off, HOOK_TOKENS[i].len);
            tok[HOOK_TOKENS[i].len] = '\0';
            if (strstr(line, tok)) { fclose(f); return true; }
        }
    }
    fclose(f);
    return false;
}
```

### 7.5 Anti-Frida (`func#99 @ 0x115770`)

```c
// XOR-0x37 blob @0x17365, 41 bytes. NO delimiters, NO guard bytes.
static const uint8_t FRIDA_BLOB[41] = { /* .rodata:0x17365 */ };

static const struct { uint16_t off, len; } FRIDA_TOKENS[3] = {
    {  0, 11 },   // adrp/add -> 0x17365  "gum-js-loop"
    { 11, 15 },   //            0x17370   "libfrida-gadget"
    { 26, 15 },   //            0x1737f   "re.frida.server"
};

bool sub_115770_isFrida(void) {          // func#99
    char blob[48];
    decode_blob(FRIDA_BLOB, sizeof FRIDA_BLOB, 0x37, blob);
    // blob == "gum-js-looplibfrida-gadgetre.frida.server"  (packed, 41 chars)

    for (int i = 0; i < 3; i++) {
        char tok[32];
        memcpy(tok, blob + FRIDA_TOKENS[i].off, FRIDA_TOKENS[i].len);
        tok[FRIDA_TOKENS[i].len] = '\0';

        if (i == 0 && thread_named(tok))            return true;  // gum-js-loop
        if (i == 1 && maps_contains_module(tok))    return true;  // libfrida-gadget
        if (i == 2 && process_or_socket(tok))       return true;  // re.frida.server
    }
    return false;
}
```

Redundant second path — `func#162 @ 0x136cb8`:

```c
bool sub_136CB8_isFrida_b64(void) {
    static const char *B64[] = {
        "ZnJpZGE=",              // frida               @0x15be1
        "bGliZnJpZGEtZ2FkZ2V0",  // libfrida-gadget     @0x16d97
        "cmUuZnJpZGEuc2VydmVy",  // re.frida.server     @0x1607f
        "Z3VtLWpzLWxvb3A=",      // gum-js-loop         @0x161eb
    };
    for (int i = 0; i < 4; i++) {
        char *p = base64_decode(B64[i]);   // func#796 engine
        if (maps_or_threads_contain(p)) { free(p); return true; }
        free(p);
    }
    return false;
}
```

### 7.6 Maps integrity (`func#225 @ 0x157f38`)

```c
bool sub_157F38_mapsTampered(void) {     // func#225
    char *maps = base64_decode("L3Byb2Mvc2VsZi9tYXBz");        // /proc/self/maps  @0x15db5
    char *rwxp = base64_decode("cnd4cA==");                    // rwxp             @0x16336
    char *art  = base64_decode("bGliYXJ0LnNvIChkZWxldGVkK");   // libart.so (deleted) @0x16b75
    char *libc = base64_decode("bGliYy5zbyAoZGVsZXRlZCk=");    // libc.so  (deleted)  @0x16f69

    FILE *f = fopen(maps, "r");
    if (!f) return false;
    char line[1024]; bool bad = false;
    while (fgets(line, sizeof line, f)) {
        if (strstr(line, rwxp)) { bad = true; break; }   // RWX mapping => injected code
        if (strstr(line, art )) { bad = true; break; }   // patched ART
        if (strstr(line, libc)) { bad = true; break; }   // patched libc
    }
    fclose(f);
    return bad;
}
```

### 7.7 Hardcoded AES-256 key/IV installation (`func#157 @ 0x131d58`)

```c
// .rodata — RAW BINARY, used verbatim (func#193 performs no transformation)
static const uint8_t STATIC_AES256_KEY[32] = {      // 0x17428
    0x1b,0x2e,0x63,0x6b,0x13,0x22,0x0c,0x34,
    0x08,0x09,0x38,0x1c,0x2a,0x2a,0x0c,0x6a,
    0x0f,0x22,0x14,0x1c,0x3e,0x0f,0x09,0x34,
    0x2a,0x36,0x0e,0x0d,0x6f,0x15,0x14,0x1b
};
static const uint8_t STATIC_AES_IV[16] = {          // 0x17448
    0x0d,0x17,0x0c,0x1f,0x2d,0x0c,0x1d,0x6a,
    0x68,0x3f,0x1d,0x1c,0x36,0x0c,0x37,0x08
};

struct CipherCtx {           // built on the stack of func#157 at x29-0x28 / x29-0x40
    uint8_t key[32];
    uint8_t iv [16];
    /* + expanded round keys, state, tag … */
};

void sub_131D58_initStaticCipher(struct CipherCtx *ctx /*x8 sret*/, void *in /*x0*/) {
    copy_obfuscated(STATIC_AES256_KEY, 32, ctx->key);   // bl func#193 @0x14193c
    copy_obfuscated(STATIC_AES_IV,   16, ctx->iv );     // bl func#193

    sub_13D098_ctor (ctx);          // func#176
    sub_13D2FC_begin(ctx);          // func#177 -> func#191 (4,672 B core)
    …
    sub_13D634_finish(ctx);         // func#178   (called 3×)
}
```

### 7.8 LibTomCrypt AES key expansion (`func#14 @ 0x32158`)

```c
// Supports all three key sizes; round count selected by the classic 10/12/14 test.
int rijndael_setup(const uint8_t *key, int keylen, int num_rounds, symmetric_key *skey) {
    if (keylen != 16 && keylen != 24 && keylen != 32) return CRYPT_INVALID_KEYSIZE;

    skey->rijndael.Nr = (keylen == 16) ? 10 : (keylen == 24) ? 12 : 14;   // cmp #0xa / mov #0xc / mov #0xe

    memcpy(skey->rijndael.eK, key, keylen);

    for (int i = keylen/4, r = 0; i < 4*(skey->rijndael.Nr + 1); ) {
        uint32_t tmp = skey->rijndael.eK[i-1];
        if (r == 0) {
            r = 1;
            tmp = (setup_Sbox[(tmp>> 8)&0xff]      ) |
                  (setup_Sbox[(tmp>>16)&0xff] <<  8) |
                  (setup_Sbox[(tmp>>24)&0xff] << 16) |
                  (setup_Sbox[(tmp    )&0xff] << 24);
            tmp ^= setup_rc[r++];                       // Rcon @0x135b0 (LibTomCrypt order)
        } else if (keylen == 32 && r == 1) {
            r = 2;
            tmp = (setup_Sbox[(tmp    )&0xff]      ) |
                  (setup_Sbox[(tmp>> 8)&0xff] <<  8) |
                  (setup_Sbox[(tmp>>16)&0xff] << 16) |
                  (setup_Sbox[(tmp>>24)&0xff] << 24);
        } else r = 0;

        skey->rijndael.eK[i] = skey->rijndael.eK[i - keylen/4] ^ tmp;
        i++;
    }
    /* decrypt key schedule derived via setup_log/setup_alog @0x13b10/0x13b30/0x13f30/0x14330/0x14730 */
    return CRYPT_OK;
}
```

Tables used (all in `.rodata`): `setup_Sbox @0x128b0`, `setup_RSbox @0x139b0`, `setup_rc @0x135b0`, `setup_log @0x13b10`, `setup_alog @0x13b30/0x13f30/0x14330/0x14730`, `Te0-Te3 @0x118b0/0x11cb0/0x120b0/0x124b0`, `Td0-Td3 @0x129b0/0x12db0/0x131b0/…`.

### 7.9 High-level AES-CBC encrypt (`func#30 @ 0x38fa4`)

```c
// callers: func#56, #57, #59, #60, #61, #63, #67  (7 of the JNI entry points)
int aes_cbc_encrypt(const unsigned char *pt, unsigned char *ct,
                    unsigned long len, symmetric_CBC *cbc) {
    if (len % 16) return CRYPT_INVALID_ARG;

    rijndael_setup(cbc->key, cbc->keylen, cbc->rounds, &cbc->skey);   // func#14
    aes_set_encrypt_key(...);                                          // func#15

    while (len) {
        for (int i = 0; i < 16; i++) cbc->IV[i] ^= pt[i];              // CBC chain
        rijndael_ecb_encrypt(cbc->IV, ct, &cbc->skey);                 // func#12 -> func#10 (Te tables)
        memcpy(cbc->IV, ct, 16);
        ct += 16; pt += 16; len -= 16;
    }
    memset(...);                                                       // 2× memset (key wipe)
    return CRYPT_OK;
}
```

`func#36 @ 0x3a838` is the mirror (calls `func#16` → `func#13` → `func#11`, Td tables).
`func#85 @ 0x10c470` / `func#94 @ 0x110b70` wrap these with an **envelope**: length prefix + `order_stamp` + `sign` digest + Base64 outer layer (`func#796`), then hand the result to Java as a `jstring` (`NewStringUTF`).

### 7.10 SHA-256 (`func#212 @ 0x1509cc`, pipeline `func#204 @ 0x148bf4`)

```c
static const uint32_t K[64] = { /* .rodata:0x174c4, standard SHA-256 K */ };

static void sha256_compress(hash_state *md, const unsigned char *buf) {   // func#212
    uint32_t W[64], a,b,c,d,e,f,g,h;
    for (int i = 0; i < 16; i++) STORE32H(W[i], buf + 4*i);
    for (int i = 16; i < 64; i++)
        W[i] = Gamma1(W[i-2]) + W[i-7] + Gamma0(W[i-15]) + W[i-16];
    /* a..h = md->state[0..7]  — init values .rodata:0x17220 */
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + Sigma1(e) + Ch(e,f,g) + K[i] + W[i];
        uint32_t t2 = Sigma0(a) + Maj(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    /* md->state[i] += {a..h} */
}
```

Init state comes from `.rodata:0x17220` = `6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19` (standard).

### 7.11 Certificate pin + signature check (`func#245`, `func#226`, `func#73`)

```c
// func#245 @0x16bbdc — called ONLY by func#226
static const char *PIN_B64_L2 =
  "WkRnME5UVTVNV1V3T0RZd016TmhPVEF6Tldaa05tSTJObU16WXpOa056TmhZVE16WVdZNU1EYzVOR1Ey"
  "WWprNE5tVTJORGMzT1dWbFlUWmlaV00xWlE9PQ==";              // .rodata:0x15084

bool check_pin(JNIEnv *env, jobject ctx) {
    char *lvl1 = base64_decode(PIN_B64_L2);          // -> "ZDg0NTU5MWUwODYwMzNhOT…"
    char *pin  = base64_decode(lvl1);                // -> "d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e"

    // ---- APK signature (func#73 / func#226) ----
    jclass  pmc = FindClass("android/content/pm/PackageManager");          // 0x157df
    jobject pm  = CallObjectMethod(ctx, getPackageManager);
    jobject pi  = CallObjectMethod(pm, getPackageInfo, pkgName, GET_SIGNATURES); // 0x15b8b / 0x15eda
    jobjectArray sigs = GetObjectField(pi, "signatures");                   // 0x15f83 / 0x14e80
    jbyteArray   raw  = CallObjectMethod(sigs[0], toByteArray);             // 0x15fa3

    jclass md = FindClass("java/security/MessageDigest");                  // 0x16629
    jobject d = CallStaticObjectMethod(md, getInstance, NewStringUTF("SHA-256")); // 0x16645
    jbyteArray h = CallObjectMethod(d, digest, raw);

    return hex_lower(h) == pin;      // constant-time compare not observed
}

// func#253 @0x172460 / func#254 @0x173c40 — OkHttp pinning
//   new CertificatePinner.Builder()                      // 0x15113
//       .add("i.instagram.com", "sha256/" + pin)         // 0x1536c
//       .add("www.instagram.com", "sha256/" + pin)
//   OkHttpClient.Builder().certificatePinner(pinner)     // 0x16240 / 0x1649e
```

### 7.12 Base64 alphabet installer (`func#26 @ 0x3896c`, 68 bytes — the whole function)

```c
void base64_init_tables(void) {                    // func#26
    const char *alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        "abcdefghijklmnopqrstuvwxyz"
                        "0123456789+/";            // .rodata:0x1501a (canonical)
    size_t n = strlen(alpha);                      // bl func#17 @0x35d58 -> PLT strlen
    memcpy(&g_base64_ctx /* .data:0x1c0320 */, alpha, n);
    build_decode_table(&g_base64_ctx, n);          // -> .data.rel.ro:0x1b6160
}
```

### 7.13 Detection orchestration (who checks what, when)

```
JNI m2  func#57  ─┬─> func#200  anti-hook  (xposed/lsposed/edxposed/riru/substrate/libcso/libbridge/zygisk)
                  ├─> func#99   anti-frida (gum-js-loop/libfrida-gadget/re.frida.server)
                  ├─> func#162  anti-frida (base64 variant)
                  ├─> func#157  static AES-256 key/IV install  <== hardcoded secret
                  ├─> func#154 ─> func#169 root (9× su paths via access())
                  ├─> func#85   AES encrypt + envelope
                  ├─> func#73   APK signature SHA-256
                  └─> func#98   clock() timing

JNI m12 func#67  ─┬─> func#225  maps integrity (rwxp / libart.so (deleted) / libc.so (deleted))
                  ├─> func#226  cert-pin + signature (46 KB) ─> func#245 pin hash
                  │                                └─> func#99 anti-frida
                  │                                └─> func#85 AES
                  │                                └─> func#98 clock()
                  ├─> func#244  build https://i.instagram.com/api/v2/ URL
                  └─> inflate() gunzip response body

JNI m9  func#64  ─── Build.* fingerprint  + func#157 (static AES)
JNI m14/15 func#71/#72 ──> func#253/#254 CertificatePinner$Builder
JNI m20 func#154 ───> func#169 root check
```

**Every large JNI entry point re-runs the checks.** There is no single "isCompromised()" gate to patch; you must neutralise `func#200`, `func#99`, `func#162`, `func#225`, `func#169`, `func#73`/`func#245`, `func#253`/`func#254`, and `func#98` independently.

---

## 8. Weaknesses & practical bypass notes

| # | Finding | Severity | Why it matters |
|---|---|---|---|
| 1 | **AES-256 key + IV hardcoded in `.rodata`** (`0x17428` / `0x17448`), consumed verbatim | **Critical** | Static across all installs and all three ABIs. 48 bytes of extraction ⇒ full decrypt. Fixed IV ⇒ CBC plaintext-equality leak + replay. |
| 2 | **Second static 32-byte key** @ `0x17307` on the `func#54/#55` path | **Critical** | Same problem, different code path. |
| 3 | Cert pin is a **double-Base64 of a hex string**, not a DER/SPKI blob | High | Trivially decoded offline; no need to run the app. |
| 4 | String protection is **single-byte XOR** with the key inlined per site | High | One `bic/bic/orr` pattern to search for; a 10-line script decodes everything (§5). |
| 5 | Root check is **`access()` on 9 fixed paths only** | High | Magisk Hide / a renamed `su` / Zygisk DenyList defeats it completely. No `su -c`, no package check, no mount-namespace probe. |
| 6 | Frida detection is **name-based** (`gum-js-loop`, `libfrida-gadget`, `re.frida.server`) | High | Renamed frida-server + `-l` gadget or a `stalker`-only script is invisible. No port 27042 probe, no `ptrace` self-attach, no inline-hook scan. |
| 7 | Hook detection is **`strstr` over `/proc/self/maps`** | High | Does not inspect PLT/GOT for actual inline hooks; a memory-only injector that unlinks its mapping is invisible. |
| 8 | **No** emulator detection, **no** `TracerPid`, **no** debugger self-attach, **no** Play Integrity | Medium | Large gap for a "hardened" library — an emulator + attached `lldb` is entirely undetected. |
| 9 | Signature check uses deprecated `PackageInfo.signatures` (not `GET_SIGNING_CERTIFICATES`) | Medium | Vulnerable to the classic Janus/fake-ID style signature-scheme-1 confusion on API < 28 paths. |
| 10 | CFF inflates 12 functions to 50.8 % of the binary | Low (cost) | Makes automated decompilation noisy but is **fully reversible** — the state variable lives in a callee-saved register and each block ends with `mov wN,#imm; b dispatcher`. |
| 11 | Pin comparison is not constant-time | Low | Theoretical; not exploitable remotely here. |

**Neutralisation order if you must run it dynamically:**
1. Hook `func#193` (`0x14193c`) to dump `src/len/dst` — recovers every key/IV install at runtime, including any you missed statically.
2. Force-return `false` from `func#200` (`0x145f88`), `func#99` (`0x115770`), `func#162` (`0x136cb8`), `func#225` (`0x157f38`), `func#169` (`0x13ba30`).
3. Patch `.rodata:0x15084` pin to your proxy's SPKI **or** hook `func#253`/`func#254` to skip `CertificatePinner$Builder.add`.
4. Neutralise `func#98` (`0x114fbc`) `clock()` delta.
5. Only then attach Frida — remember `func#226` calls `func#99` **immediately before** applying pins.

---

## 9. Artifacts produced

All under `work/analysis/` (regenerable from the APK):

| File | Content |
|---|---|
| `annotated_arm64.txt` | **400 K lines** — full Capstone disassembly of all 1,090 functions, every `adrp/add` annotated with its resolved target, every `bl` with its PLT name |
| `full_disasm_arm64.txt` | raw disassembly (pre-annotation) |
| `model_arm64.json` / `model_x64.json` | ELF models: sections, imports, exports, function boundaries |
| `funcmap.json` | per-function profile: instruction count, mnemonic histogram, branch counts, data refs, PLT usage, call targets, inverted xrefs |
| `final_detection_map.txt` | **data-ref inversion table** — every crypto/detection blob → owning function → callers (the authoritative attribution) |
| `all_decoded_strings.txt` | 3-layer corpus: plaintext strings · Base64 chains (1–4×) · XOR blobs |
| `xor_strings.txt` | universal single-byte-XOR scanner output over all 1,585 `.rodata` units |
| `xor_decoded_final.txt` | hexdumps + 256-key sweeps for each candidate blob |
| `decoded_refs.txt` | per-function decoded string references incl. nested Base64 unwrapping |
| `obf_report.txt` / `obf_rows.json` | quantitative obfuscation metrics per function + population aggregates |
| `call_freq.json` | internal call frequencies (top helpers: `#676`×2338, `#23`×371, `#1046`×313, `#76`×231, `#17`×188) |
| `xrefs.json` / `calls.json` / `plt_map.json` | 1,901 xref targets · 8,962 call sites · 88 PLT entries |
| `jni_natives.txt` | all 22 `JNINativeMethod` entries parsed from `.data.rel.ro` via LIEF relocations |
| `strings_dump.txt` | `strings -a -n 4` with file offsets |
| `rodata_strings.txt`, `rodata_encrypted_regions.txt`, `jni_strings.txt` | entropy-mapped `.rodata` inventory |
| scripts | `elf_model.py`, `disasm.py`, `xref.py`, `funcmap.py`, `decode_refs.py`, `decrypt_strings.py`, `dex_scan.py`, `dex_jni.py`, `dex_layer.py`, `dex_models.py` |

### Reproduction

```bash
python3 -m venv .venv && .venv/bin/pip install capstone==5.0.7 lief==1.0.0 androguard==4.1.4
unzip TopFollow_v845-Beta.apk -d work/apk_extracted
.venv/bin/python work/analysis/elf_model.py     work/apk_extracted/lib/arm64-v8a/libtopfollow.so work/analysis/model_arm64.json
.venv/bin/python work/analysis/funcmap.py       # -> funcmap.json
.venv/bin/python work/analysis/decrypt_strings.py
```

---

## 10. Corrections to earlier working notes

Recorded so the mistakes are not repeated:

1. **Blob `0x1742b` is *not* Instagram API paths.** It is 68 bytes consumed by `func#157`/`func#158` and does **not** decode under any single-byte XOR (all 256 keys + positional variants swept). Status: *encrypted, key not recovered*. The real Instagram endpoints are Base64-encoded at `0x159ec` / `0x15c02` / `0x15de3` (§5.2).
2. **Anti-hook scanning is `func#200 @ 0x145f88`, not `func#60`.** `func#60` is JNI m5 (44,957 insns) and merely *Base64-decodes* some of the same tokens. The XOR-0x5A blob owner is `func#200` (9 data refs inside the blob).
3. **Anti-Frida scanning is `func#99 @ 0x115770`, not `func#162`.** `func#99` owns the XOR-0x37 blob; `func#162` is a redundant Base64-based second path.
4. **`0x17123` / `0x1716e` / `0x1719e` are not crypto material.** They are genuine `.rodata` targets of `adrp/add` inside `func#30`, but the bytes are structured byte-pair fill (`0x1719e` is 40 repetitions of `c8 00`; `0x1716e` repeats `20 01`, `39 01`, `22 01`, …) — alignment/length tables, not key material. None decodes under any single-byte XOR. The real key material is at `0x17428` / `0x17448` / `0x17307`.
5. **`0x12380` / `0x127c0` are not SHA-256 constants** — they are AES Te/Td table interiors. SHA-256 `H0` is at **`0x17220`** and `K[64]` at **`0x174c4`** (both verified exact-standard).
6. **`syscall` (`func#746`) and `dl_iterate_phdr` (`func#1074`) are not anti-debug.** libc++ condvar internals and the unwinder respectively.
7. **The Base64 alphabet is canonical**, not a custom permutation — the apparent permutation was the XOR-0x20 storage form at `0x17327`.
8. **`Frid…` in the binary is `Friday`** (`0x15e68`, libc++ weekday table). There is no plaintext `frida` string.
9. **`func#1046 @ 0x1adb78`** (`fprintf`+`fflush`+`abort`, 313 callers) is the libc++ assertion handler — not a security routine.
10. **The 1,008-byte blob at `0x14770`** and `Te4 @0x145b0` / `Td4 @0x146b0` have **no xrefs** — dead data, not a hidden payload.
11. **Neither packed XOR blob has a `0x1A` (or any) delimiter.** An earlier reading assumed `0x1A`-separated tokens; byte `0x1A` does not occur in either blob. `func#200` and `func#99` hold **one `adrp`/`add` per token** and slice the decrypted buffer by hard-coded offset — see the ref→token tables in §5.1.
12. **The Frida blob starts at `0x17365`, not `0x17366`.** Reading the region from `0x17366` clips the leading `g` and yields `um-js-loop`, which is what an earlier pass reported.
13. **The hook blob's `U`/`Z` bytes are guards, not tokens.** `0x1746f` = `0x55` (`'U'`) and `0x174c3` = `0x5A` (`'Z'`) decrypt to `U`/`Z` framing 83 bytes of packed payload; the first real token (`/proc/self/maps`) begins at `0x17470`.
14. **SHA-256 constants are *not* at `0x12380`/`0x127c0`** (those are AES Te/Td table interiors that merely resemble constants). Correct addresses — `H0 @ 0x17220`, `K[64] @ 0x174c4` — were confirmed by exact little-endian dword match against the standard values, and `sha256_compress` is `func#212` (the sole referrer of `K`), not `func#73`/`func#226` (which upcall Java `MessageDigest` instead).

---

*End of report.*
