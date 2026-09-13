# `libtopfollow.so` — Reverse Engineering Report

**Target:** `TopFollow_v845-Beta.apk` → `lib/arm64-v8a/libtopfollow.so`
**Analysed:** 2026-09-12 → 2026-09-13 (revision 4) · **static analysis + full AArch64 emulation** (Unicorn harness, `work/analysis/emu.py`) · no debugger on a device
**Scope:** obfuscation techniques · detection mechanisms · all encryption (AES + everything else) · request/response crypto path end-to-end

> **Revision 2 — everything in §4, §7.7, §7.9 and §11 is backed by _executing_ the code.**
> Every cipher claim below was verified by running the real obfuscated function inside an
> AArch64 emulator against known-answer tests. Where revision 1 guessed, revision 2 measures.
>
> **Revision 3 — the JNI slot mapping, the signature-pin encoding and the string tables were
> re-derived from the relocations and corrected** (§10 items 29–33), and the analysis became a
> deployable Frida harness (§9, §11.10).
>
> **Revision 4 — `func#36` resolved, GCM proven native, and the detection layer rebuilt around
> how the library actually reads files.** The library imports *no* `fopen`, `fgets`, `strstr`,
> `stat` or `lstat`, so the maps-hiding strategy documented in revisions 1–3 could never have
> fired; it now filters the `read()` buffer instead. All superseded conclusions are listed in
> **§10 Corrections, items 1–40**, with the new evidence in **§11.11** and **§11.12**.

---

## 0. Executive summary

| | |
|---|---|
| Library | `libtopfollow.so`, 1,805,400 bytes, AArch64 ELF shared object |
| Toolchain | Android NDK **r23c**, clang/LLD **12.0.9**, build-id `8568313…` |
| Symbols | **Stripped.** Exactly **one** export: `JNI_OnLoad @ 0x3e1d4`. 92 dynamic imports. |
| Code | 1,090 functions, **395,331 instructions** recovered |
| Obfuscator | A **control-flow-flattening + MBA + string-encryption** obfuscator (LLVM-style, OLLVM/Pluto/Armariris class). 12 flattened functions = **50.8 % of all code** · 5,299 blinded constants · 170 functions carry the opaque-predicate idiom · **467 MBA-XOR idioms in 31 functions, 91 % of them inside the AES/SHA cores** (§3.5) · **712 `b .` infinite-loop traps in 79 functions, 148 reachable** (§3.8) |
| Crypto | **AES (LibTomCrypt, T-table — all 9 tables regenerated and matched bit-for-bit, §11.8)** + **SHA-256 (LibTomCrypt)** + **SHA-1** (`func#199`/`#201`/`#202`) + **Base64 (two engines, up to 4 nested layers)** + **single-byte XOR `0x5A` string encryption** (`func#193`, §11.1) |
| **Cipher #1 (proven)** | `func#85` / `func#94` = **AES-ECB + PKCS#7 + lowercase-hex output**, key taken *verbatim* from the caller. Accepts 16/24/32-byte keys (AES-128/192/256). **Byte-exact match** against FIPS-197. §11.2 |
| **Cipher #2 (proven)** | `func#30` = **AES-128-CBC, key = 16 × `0x00`, IV = 16 × `0x00`, PKCS#7, lowercase-hex output**. The key argument is **ignored**. §11.3 |
| **Cipher #3 (rev 4)** | `func#36` = **AES-256-ECB decrypt + PKCS#7 unpad over hex-decoded input** — and its key is **not a constant**: `rijndael_setup` is entered with `keylen = 32` and a user-key pointer into `func#36`'s own stack frame. Non-hex input returns empty; a length that is not a multiple of 16 is echoed verbatim; valid padding is stripped. It is a **padding oracle**, reachable as `q.k` (slot 15) → `#252` → `#36`. §11.11(a), §10 item 34 |
| Hardcoded secrets | **`0123456789abcdef`** — a literal AES-128 key in plaintext `.rodata` (`0x161ca`, `0x17ae0`), used by the cert-pinner `func#226`/`func#73` and the OkHttp builders `func#71`/`func#72`. §4.2A |
| | **`At91IxVnRSbFppV0UxNFdUSnplTW5ONA`** (32 ch → Base64 → **24 B = AES-192**) and **`WMVEwVG02eGFlVmR`** (16 ch → Base64 → **12 B = GCM 96-bit nonce**), stored XOR-0x5A at `0x17428`/`0x17448`, recovered *and re-verified by emulation*. §4.2 |
| | **Four more 12-byte secrets** returned by argument-independent getters — `func#86` → `5VEJK9Uk4d0elpVT`, `func#159` → `OVmx02wMFR6WaGtW`, `func#160` → `V0V4V2pOa1ptZGsl`, `func#161` → `xV2xKTlZsBUVk1He`; plus a second GCM nonce at `0x17458` (`func#158`). One emulated call each recovers them all. §11.5 |
| | Signature pin **`d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e`** at `0x15084` — stored in **plaintext** as Base64(Base64(hex)), i.e. **2** layers, not 3. It is **`SHA-256` of this APK's own signer certificate DER (864 B)**, extracted from the v2 Signing Block and matched byte-for-byte. §6.5, §10 items 29–31 |
| Detection | anti-Frida, anti-Xposed/LSPosed/EdXposed/Riru/Zygisk/Substrate, root (`su` paths), `/proc/self/maps` integrity (`rwxp`, `(deleted)` libs), APK signature check, device fingerprinting, certificate pinning, `clock()` timing. **Reads maps with `__open_2` + `__read_chk`/`read`, never `fopen`/`fgets`, and searches it with inlined byte loops — the 88-symbol import table has no `strstr` at all** (§10 item 39). Every token is stored as a plain **Base64 C string**, so none of the literals exists in the binary (§10 item 40) |
| App | `com.nivaroid.topfollow` v8.4.5 (845), minSdk 24 / targetSdk 35. An Instagram follower/exchange panel client that talks to `i.instagram.com/api/v2/` and `www.instagram.com/graphql/query`. |

**Bottom line:** this is a professionally *obfuscated* but cryptographically **weak** JNI blob.
Three independent, statically-embedded secrets protect all of its traffic:

1. a **literal `0123456789abcdef` AES key** sitting in plaintext `.rodata`;
2. an **all-zero AES-128-CBC key + all-zero IV** hard-wired into `func#30` — the function used by
   **7 of the 22 JNI entry points**, including the response handler `func#67`;
3. a **static Base64 AES-192 key + static 12-byte nonce** behind one XOR byte.

`func#85` additionally uses **ECB**, which leaks plaintext structure — proven, not inferred:
encrypting `"A"*32` yields the same 16-byte ciphertext twice, and a PKCS#7 pad block encrypts to
a constant regardless of what precedes it (§11.2). Nothing here is a real key-exchange: any of
these three lets an attacker decrypt or forge arbitrary app traffic by extracting ~100 bytes
from the library. The obfuscation is expensive (huge flattened functions)
but shallow (one XOR byte, one MBA idiom, one CFF pass) and, as §11 shows, it does not survive
ten minutes of emulation.

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

### 2.2 The 22 natives → Java method map  *(revision 3: rebuilt from the recovered table)*

Java side: `Lcom/nivaroid/topfollow/helper/q;` — public methods `a`…`v`, each a one-line
delegate to a `private static native` method whose name is an **obfuscated hex slug**
(`x00105e9b`, `x0011a4c2`, …). The slug is R8 output and carries no meaning.

> **Correction (revision 3).** Revision 2's table paired each slug with the *wrong* function
> number: it listed slot 0 (`x0011a4c2`) as `func#56`, when the recovered `fnPtr` for slot 0
> is `0x3eab4` = **`func#51`**. Every row was shifted. The `fnPtr` **addresses** quoted in
> revision 2 were correct, so all the address-keyed analysis (§4, §5, §6, §11) still holds;
> only the `func#` labels attached to the JNI slugs were wrong. The table below is derived
> mechanically: `work/analysis/jni_natives.txt` (relocations → 22 `JNINativeMethod` slots)
> ⋈ `work/analysis/funcmap.json` (`start` → `func#`) ⋈ the DEX delegate bodies of `helper/q`.

| slot | Java slug | Java signature | `q.` method | `fnPtr` | native | size (B) | insns |
|---|---|---|---|---|---|---|---|
| 0 | `x0011a4c2` | `()J` | `q.j()` | `0x3eab4` | **`func#51`** | 1,408 | 352 |
| 1 | `x0014e2e9` | `()String` | `q.e()` | `0x3f034` | **`func#52`** | 916 | 229 |
| 2 | `x0016d3b9` | `()String` | `q.d()` | `0x3f3c8` | **`func#53`** | 704 | 176 |
| 3 | `x0012d3e0` | `(String)String` | `q.o(String)` | `0x3f688` | **`func#54`** | 6,788 | 1,697 |
| 4 | `x0011e28b` | `(String)String` | `q.n(String)` | `0x4110c` | **`func#55`** | 9,388 | 2,347 |
| 5 | `x00120b1e` | `(JsonObject,String)V` | `q.i(JsonObject,String)` | `0x435b8` | **`func#56`** | 47,808 | 11,952 |
| 6 | `x0012e5a1` | `(JsonObject)V` | `q.v(JsonObject)` | `0x4f078` | **`func#57`** | 160,912 | 40,228 |
| 7 | `x00135e2a` | `(JsonObject,InstagramAccount,String)V` | `q.u(…)` | `0x76508` | **`func#58`** | 37,668 | 9,417 |
| 8 | `x00105e9b` | `(String)String` | `q.c(String)` | `0x7f82c` | **`func#59`** | 9,260 | 2,315 |
| 9 | `x0015b1e9` | `(JsonObject,String,String)V` | `q.r(…)` | `0x81c58` | **`func#60`** | 179,828 | 44,957 |
| 10 | `x0015a3b7` | `(JsonObject,InstagramAccount,Order)V` | `q.t(…)` | `0xadacc` | **`func#61`** | 73,008 | 18,252 |
| 11 | `x0017b62c` | `(String,String,String)String` | `q.s(String,String,String)` | `0xbf7fc` | **`func#62`** | 28,584 | 7,146 |
| 12 | `x0011f42b` | `()String` | `q.m()` | `0xc67a4` | **`func#63`** | 22,280 | 5,570 |
| 13 | `x0012f5b7` | `()String` | `q.b()` | `0xcbeac` | **`func#64`** | 34,812 | 8,703 |
| 14 | `x0014b4f3` | `(String)String` | `q.a(String)` | `0xd46a8` | **`func#65`** | 14,912 | 3,728 |
| 15 | `x0011f1a2` | `(Order)String` | `q.h(Order)` | `0xd80e8` | **`func#66`** | 33,020 | 8,255 |
| 16 | `x0015e49c` | `(Response,Order,InstagramAccount)String` | `q.p(…)` | `0xe01e4` | **`func#67`** | 117,628 | 29,407 |
| 17 | `x0010e27f` | `()String` | `q.f()` | `0xfcd60` | **`func#68`** | 688 | 172 |
| 18 | `x00113f7a` | `()String` | `q.g()` | `0xfd010` | **`func#69`** | 1,328 | 332 |
| 19 | `x0014c1f9` | `(Response)String` | `q.q(Response)` | `0xfd540` | **`func#70`** | 3,368 | 842 |
| 20 | `x00126f7c` | `(Z,String)Retrofit` | `q.k(String,Z)` | `0xfe268` | **`func#71`** | 12,624 | 3,156 |
| 21 | `x0018d3f7` | `(I)Retrofit` | `q.l(I)` | `0x1013b8` | **`func#72`** | 10,016 | 2,504 |

The natives are therefore **exactly `func#51 … func#72` in slot order** — 22 consecutive
function IDs. `func#73 @ 0x103ad8` is the first *non*-JNI function after them, and
`func#50` and below are the pre-`JNI_OnLoad` helpers (`JNI_OnLoad` itself is
`0x3e1d4`, immediately before `func#51 @ 0x3eab4`).

### 2.2A What each JNI native actually calls (the request/response map)

Derived from `funcmap.json`'s direct-call edges. This is the single most useful table for
instrumentation: it tells you which Java entry point reaches which cipher and which
anti-analysis check.

| slot | native | `func#85` ECB-enc | `func#94` ECB-dec | `func#30` CBC-zero | `func#157/#158` GCM ctx | `func#73` sig-verify | `func#226` sig+pin | anti-analysis |
|---|---|---|---|---|---|---|---|---|
| 0 | `#51` `q.j()→long` | | | | | **✓** | | |
| 1 | `#52` `q.e()` | | | | | | | |
| 2 | `#53` `q.d()` | | | | | | | |
| 3 | `#54` `q.o(String)` | **✓** | | | | | | getter `#86`, `#87` |
| 4 | `#55` `q.n(String)` | | **✓** | | | | | getter `#86`, `#87` |
| 5 | `#56` `q.i(JsonObject,String)` | | **✓** | **✓** | | | | `#99` anti-Frida, `#98` clock, `#97` ANDROID_ID |
| 6 | `#57` `q.v(JsonObject)` | **✓** | | **✓** | **✓ ✓** | **✓** | | `#99`, `#162`, `#200`, `#98`, `#97` |
| 7 | `#58` `q.u(…)` | **✓** | | | | | | `#98` clock, `#97` |
| 8 | `#59` `q.c(String)` | | | **✓** | | | | `#98` clock |
| 9 | `#60` `q.r(…)` | **✓** | | **✓** | | | | `#98`, `#97` |
| 10 | `#61` `q.t(…)` | | | **✓** | | | | `#200` anti-hook, `#98` |
| 11 | `#62` `q.s(3×String)` | **✓** | | | | | | `#98` clock |
| 12 | `#63` `q.m()` | | | **✓** | | | | `#98` clock |
| 13 | `#64` `q.b()` | | | | **✓** `#157` | | | `#98`, `#97` |
| 14 | `#65` `q.a(String)` | **✓** | | | | | | `#162` anti-Frida-b64, `#98`; getters `#159/#160/#161` |
| 15 | `#66` `q.h(Order)` | | | | | | | — |
| 16 | `#67` `q.p(Response,Order,Account)` | **✓** | | **✓** | | | **✓** | `#225` maps-integrity, `#98` |
| 17 | `#68` `q.f()` | | | | | | | |
| 18 | `#69` `q.g()` | | | | | | | |
| 19 | `#70` `q.q(Response)` | | | | | | | |
| 20 | `#71` `q.k(String,Z)` | | | | | | | `#253` `CertificatePinner$Builder`, `#254` `certificatePinner` |
| 21 | `#72` `q.l(I)` | | | | | | | `#254` `certificatePinner` |

Read off this table:

* **Encrypt side (`func#85`, AES-ECB):** slots 3, 6, 7, 9, 11, 14, 16 → `q.o`, `q.v`, `q.u`,
  `q.r`, `q.s`, `q.a`, `q.p`.
* **Decrypt side (`func#94`, AES-ECB):** slots 4, 5 → `q.n`, `q.i`.
* **`func#30` (keyless AES-128-CBC):** slots 5, 6, 8, 9, 10, 12, 16 — **7 of 22**, exactly as
  §11.3 measured. The response handler `func#67` (`q.p`) is one of them.
* **GCM context builders (`func#157`/`func#158`):** only slot 6 (`func#57`, `q.v`) installs
  both, and slot 13 (`func#64`, `q.b`) installs the encrypt-side one. So `q.v(JsonObject)`
  is *the* place where the AES-192 key at `0x17428` and the nonces at `0x17448`/`0x17458`
  enter a live context — hook it first.
* **APK-signature verification is reachable from three JNI entry points:**
  `func#73 @ 0x103ad8` directly from slots 0 (`q.j`) and 6 (`q.v`), and the much larger
  `func#226 @ 0x159c10` from slot 16 (`q.p`, the response handler). `func#226` →
  `func#245 @ 0x16bbdc` (the pin hash, its **only** caller) and → `func#99` (anti-Frida)
  immediately before it applies pins (§6.5, §6.6).
* **`func#57` (slot 6, `q.v(JsonObject)`) is the hub of the whole library.** 160,912 bytes /
  40,228 instructions, and the only JNI native that reaches *everything*:
  `func#73` (signature), `func#157` **and** `func#158` (both GCM contexts), `func#85` +
  `func#30` (both ciphers), `func#97` (ANDROID_ID), `func#99` + `func#162` + `func#200`
  (all three anti-analysis scanners), `func#152`, `func#153`, `func#154` and `func#156`.
  If you can only hook one JNI native, hook this one.
* **Root check (`func#169 @ 0x13ba30`) is *not* called from any JNI native directly.** Its
  only caller is `func#154 @ 0x12a068`, whose only caller is `func#57` — so the root check
  is reachable from Java **only** through `q.v(JsonObject)` (slot 6). Same shape for
  `func#156` (3-arg token/sign): its only caller is `func#57`.
* **`func#200` (anti-hook)** is reached directly from slots 6 and 10 only; **`func#162`
  (anti-Frida, Base64 tokens)** from slots 6 and 14; **`func#225` (maps integrity)** from
  slot 16 only.
* **The `order_stamp2` timestamp is `func#166 @ 0x13a358`**, called by `func#152` and
  `func#247`. `func#152` is called from slots 6, 9 and 10; `func#247 @ 0x16c564` from
  `func#70` (slot 19, the `q.q(Response)` handler). So a timestamp is minted on both the
  request path (`q.v`/`q.r`/`q.t`) and the response path (`q.q`).
* **Slots 1, 2, 15, 17, 18, 19 call no cipher and no check directly** — they are the small
  constant / accessor natives (`q.e`, `q.d`, `q.h`, `q.f`, `q.g`, `q.q`). `q.q` does reach
  `func#247` → `func#166`.

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
The single-byte XOR used to decrypt strings is never emitted as a single `eor` with the key.
It is emitted as a **4-instruction MBA chain split over two immediates** whose XOR *is* the key:

```asm
; func#193 @ 0x141ccc — string decryptor core (executed & verified, see §7.2)
mov  w23, #0x3a          ; KEY_A
mov  w24, #-0x3b         ; KEY_B == ~KEY_A  (0xffffffc5)
ldrb w8,  [x21]          ; c
bic  w9,  w23, w8        ; KEY_A & ~c
and  w8,  w8,  w24       ; c & ~KEY_A
orr  w8,  w9,  w8        ; == KEY_A ^ c                 <-- MBA identity
eor  w1,  w8,  #0x60     ; ^ 0x60   =>  net key 0x3A ^ 0x60 == 0x5A
```

Three consequences that defeated our first static pass:

1. The effective key `0x5A` **never appears as an immediate anywhere in the binary**.
2. A "search `.rodata` for the XOR key" script finds nothing, and a per-site immediate scan
   finds `0x3A` and `0x60` — both wrong on their own.
3. The compiler also uses MBA for *predicates*, e.g. `c & ~0xFE` (parity test) and
   `x*(x-1) & ~0 == 0` (a tautology), so MBA presence alone does not imply data decoding.

#### How widespread is it? — measured

Scanning the whole RX segment for the `BIC (shifted register)` encoding (`0x0A200000`, mask
`0x7FE0FC00`) followed within 3 instructions by an `ORR (shifted register)`
(`0x2A000000`) — the exact shape of the decode loop above — gives:

| Metric | Value |
|---|---|
| MBA-XOR idioms in `.text` | **467** |
| Functions containing ≥1 | **31** |

Distribution (`work/analysis/mba_xor.json`):

| Function | count | what it is |
|---|---|---|
| `func#10` | **106** | AES **encrypt** core (`Te0..Te3`) |
| `func#11` | **105** | AES **decrypt** core (`Td0..Td3`) |
| `func#212` | 44 | SHA-256 compress |
| `func#14` | 42 | AES key setup |
| `func#13` | 33 | `rijndael_ecb_decrypt` |
| `func#199` | 30 | SHA-1 update |
| `func#12` | 25 | `rijndael_ecb_encrypt` |
| `func#197` | 21 | hash/digest helper |
| `func#98` | 9 | **timing check** (`clock()` delta) |
| `func#37` | 8 | |
| `func#18`, `func#84`, `func#30`, `func#90`, `func#157`, `func#158` | 3–5 each | cipher-context builders |
| `func#9`, `#125`, `#156`, `#170`, `#193`, `#194`, `#196`, `#201`, `#226` | 1–2 each | incl. the string decoder and the cert-pinner |

The concentration is the finding: **MBA is applied almost exclusively to the cryptographic
cores and the hash rounds**, not uniformly. 425 of the 467 idioms (91 %) sit in just eight
functions, all of them AES or SHA. That is deliberate — it maximises the cost of understanding
the cipher while keeping the obfuscator's runtime overhead off the hot JNI paths. It also means
an analyst can locate the crypto purely by counting this instruction pattern, without knowing
any constants.

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

### 3.8 ★ Dead code, and 712 `b .` infinite-loop traps — **quantified**

An exhaustive word-by-word scan of the whole RX segment for the encoding of an unconditional
branch with a zero displacement (`b .`, opcode `0x14000000`) found:

| Metric | Value |
|---|---|
| `b .` instructions in `.text` | **712** |
| Functions containing at least one | **79** |
| Of those, reachable (some branch targets them) | **148** — real anti-debug/tamper **traps** |
| Unreachable (pure padding) | **564** — dead code that only inflates and confuses CFG recovery |

Concentration is entirely in the security-relevant functions:

| Function | `b .` count | Role |
|---|---|---|
| `func#67` | **94** | JNI slot 16, `q.p(Response,Order,InstagramAccount)` — **the response handler** |
| `func#226` | **68** | certificate pinner / signature check |
| `func#73` | **64** | signature check |
| `func#57` | 49 | JNI slot 6, `q.v(JsonObject)` — 160 KB request builder, the library's hub |
| `func#60` | 36 | JNI slot 9, `q.r(JsonObject,String,String)` — setup/config |
| `func#56` | 33 | JNI slot 5, `q.i(JsonObject,String)` |
| `func#61` | 27 | JNI slot 10, `q.t(JsonObject,InstagramAccount,Order)` — order build |
| `func#154` | 25 | |
| `func#58` | 20 | JNI slot 7, `q.u(JsonObject,InstagramAccount,String)` |
| `func#66` / `func#87` | 19 each | order build / key getter |
| `func#94` | 15 | **AES-ECB decrypt** |

Full list: `work/analysis/selfloops.json`.

Two distinct effects, both intentional:

* **The 148 reachable ones are traps.** They are the *else* arm of an opaque predicate. If the
  predicate is ever perturbed — by a patch, a hook that changes a register, or a wrong
  emulation state — control flow lands on `b .` and the thread hangs forever instead of
  producing a wrong answer. This is why naive patching of this library "silently does nothing".
  Example, inside the string decryptor itself:
  ```asm
  0x141d40:  orr   w8, w9, w8
  0x141d44:  eor   w8, w8, #1
  0x141d48:  tbnz  w8, #0, #0x141d50     ; taken: normal epilogue
  0x141d4c:  b     #0x141d4c             ; NOT taken: hang forever
  ```
* **The 564 unreachable ones are anti-decompiler padding.** They make IDA/Ghidra emit huge
  bogus basic blocks and defeat naive "function size" heuristics — which is exactly why
  `func#67` looks like a 117 KB monster.

Also in this category: `func#1046 @ 0x1adb78` (`fprintf`+`fflush`+`abort`, 313 callers) is the
libc++ assertion handler — high fan-in, **zero** security value; ignore it. `func#224 @ 0x157628`
contains a reachable trap at `0x1576ac`.

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

**Every table below was regenerated byte-for-byte from FIPS-197 and compared with the file
contents — this is a proof, not a pattern match.**

| Artifact | Address | Size | First bytes | Verified against |
|---|---|---|---|---|
| `Te0` (encrypt T-table) | `0x118b0` | 1024 | `a5 63 63 c6` = LE `0xc66363a5` | generated `Te0[c]=(2·S[c]<<24)\|(S[c]<<16)\|(S[c]<<8)\|(2·S[c]^S[c])` — **256/256 words equal** ✔ |
| `Te1` | `0x11cb0` | 1024 | `0xa5c66363` | **== `Te0` rotated right 1 byte** — 256/256 ✔ |
| `Te2` | `0x120b0` | 1024 | `0x63a5c663` | **== `Te0` rotated right 2 bytes** — 256/256 ✔ |
| `Te3` | `0x124b0` | 1024 | `0x6363a5c6` | **== `Te0` rotated right 3 bytes** — 256/256 ✔ |
| `setup_Sbox` | `0x128b0` | 256 | `63 7c 77 7b f2 6b 6f c5` | **byte-identical to the FIPS-197 S-box** ✔ |
| `Td0` (decrypt T-table) | `0x129b0` | 1024 | `0x51f4a750` | LibTomCrypt `Td0` ✔ |
| `Td1` | `0x12db0` | 1024 | `0x5051f4a7` | == `Td0` rot-right 1 ✔ |
| `Td2` | `0x131b0` | 1024 | `0xa75051f4` | == `Td0` rot-right 2 ✔ |
| `Td3` | `0x135b0` | 1024 | `0xf4a75051` | == `Td0` rot-right 3 ✔ |
| `setup_RSbox` | `0x139b0` | 256 | `52 09 6a d5 30 36 a5 38` | **byte-identical to the inverse S-box** (verified as `S.index(i)` for all 256 `i`) ✔ |
| **`setup_rc` (Rcon)** | **`0x13b10`** | 256 | `01 02 04 08 10 20 40 80 1b 36 6c d8 ab 4d 9a 2f …` | the **extended 256-entry LibTomCrypt Rcon**, i.e. powers of 3 in GF(2⁸). This is the single most specific fingerprint: OpenSSL's `aes_core.c` ships only the 10-entry `01…36` table, so its presence proves **LibTomCrypt**, not OpenSSL/mbedTLS ✔ |

> **Correction to revision 1.** Revision 1 placed `Rcon` at `0x135b0` and `setup_log` at
> `0x13b10`. Both were wrong: `0x135b0` is `Td3` (a rotation of `Td0`), and `0x13b10` is the
> real Rcon. There is **no** `setup_log` / `setup_alog` table anywhere in the binary — a full
> search for the GF(2⁸) log and antilog permutations returns nothing. The LibTomCrypt build
> used here is the T-table variant, which does not need them.

Dead data (no xref, ignore): 1,008-byte blob `0x14770–0x14b30`.

Also note: the region around `0x16c10` is **plain ASCII, not encrypted** —
`" expression\0x21\0\0eHBvc2Vk\0BRAND\0\"hash_type\"\0Tue\0Aug\0basic_string"`.
These are JNI/JNA descriptor leftovers and were briefly mistaken for key material because
`func#14`'s third argument happens to point at `0x16c10` (it is never dereferenced as a table;
see §11.7).

**Function-level AES map:**

| Function | Address | Size | Role | Referenced tables |
|---|---|---|---|---|
| `func#10` | `0x02dc00` | 3,988 | `rijndael_ecb_encrypt` | Te0-Te3, S-box |
| `func#11` | `0x02eb94` | 4,664 | `rijndael_ecb_decrypt` | Td0-Td3, Rcon |
| `func#12` | `0x02fdcc` | 4,428 | `rijndael_ecb_encrypt` → `#10` | Te0-Te3, S-box |
| `func#13` | `0x030f18` | 4,672 | `rijndael_ecb_decrypt` → `#11` | Td0-Td3, RS-box |
| **`func#14`** | **`0x032158`** | **8,908** | **★ `rijndael_setup` (ENCRYPT key expansion)** — args probed live: `x0=skey, x1=userkey, x2=unused, x3=keylen, x4=keylen`; key-size gate is MBA-obfuscated `(~w4\|8)==0x11 \|\| w4==0x20`; writes the FIPS-197 round keys to `skey+0x0c`, stride 32, LE words (§11.7) | `setup_Sbox`, `setup_rc` |
| `func#15` | `0x034424` | 4,340 | key-schedule helper → calls `#9`, `#12` | |
| `func#16` | `0x035518` | 2,112 | **DECRYPT-side setup** → calls `#9`, `#12`, `#13` (both directions) | |
| `func#17` | `0x035d58` | — | `strlen`-based buffer helper | |
| **`func#30`** | **`0x038fa4`** | **4,508** | **★ PROVEN: AES-128-CBC encrypt, key = 16×`0x00`, IV = 16×`0x00`, PKCS#7, lowercase-hex out.** Key argument is ignored. Callers `#56 #57 #59 #60 #61 #63 #67` | `memset`,`strcpy`,`#14`,`#15` — §11.3 |
| **`func#36`** | **`0x03a838`** | **1,708** | hex-string **AES-256-ECB decrypt + PKCS#7 unpad** helper; the key buffer is a slice of its own stack frame, *not* a fixed constant (rev 4, item 34). Only caller `#252` ← JNI slot 20 `q.k` | `#14`,`#16`, 2× `memcpy` — §11.5, §11.11 |
| **`func#85`** | **`0x10c470`** | **6,556** | **★ PROVEN: AES-ECB encrypt + PKCS#7 + lowercase-hex out. Key = x1 verbatim; 16/24/32 B accepted.** Callers `#54 #57 #58 #60 #62 #65 #67 #154 #226` (9 sites) | `#14`,`#15`,`#23`,`#35`,`#43`,`#76`,`#81` — §11.2 |
| **`func#94`** | **`0x110b70`** | **9,140** | **★ PROVEN: exact inverse of `#85`** (hex in → plaintext out, round-trip verified). Callers `#55 #56 #153` | `#14`,`#16`,`#23`,`#37`,`#43`,`#76`,`#81` — §11.2 |
| `func#176` | `0x13d098` | 612 | cipher-context **constructor**: zeroes a 24-byte struct, stores key/IV → `#179 #180 #181 #182` | |
| `func#177` | `0x13d2fc` | 824 | cipher **update** → `func#191` (4,672 B core) | |
| `func#178` | `0x13d634` | 352 | cipher **final** → `#181`, `#192` | |
| `func#191` | `0x13ffb4` | 4,672 | custom-cipher core. **No table, no rotate, no multiply, no `.rodata` ref** → *not* AES/GCM/SHA. Calls only opaque-predicate helpers `#79 #172 #173` + `operator new`. §11.6 | |
| **`func#193`** | `0x14193c` | 1,824 | **★ NOT a `memcpy`.** It is the **XOR-0x5A string decoder**: `char* decode(char* src, size_t len, std::string* dst)`. Emulation-verified against `0x17428`/`0x17448`/`0x17458`/`0x17307`. §4.2, §7.2A | |

**Call graph (AES) — roles now confirmed by execution:**

Slot numbers below are the `JNINativeMethod` indices recovered in §2.2; the `m…` labels used
in revision 2 were off by one and are gone (§10 item 29).

```
                                     ┌── REQUEST ENCRYPTION ───────────────────────────┐
slot 3  q.o(String)     = func#54 ──> func#85  AES-ECB+PKCS7+hex  (key = arg)
                                   └─> func#86 ──> "5VEJK9Uk4d0elpVT"  (12-B b64 key getter)
slot 11 q.s(S,S,S)      = func#62 ──> func#85
slot 14 q.a(String)     = func#65 ──> func#85 + getters #159/#160/#161 + func#162
slot 9  q.r(JsonObj,S,S)= func#60 ──> func#85 , func#30 , func#97
slot 7  q.u(JsonObj,IA,S)=func#58 ──> func#85 , func#97
slot 6  q.v(JsonObject) = func#57 ──> func#85 , func#30 , func#157 , func#158 (GCM ctx),
                                      func#73 (sig), func#152/#153/#154/#156, func#99/#162/#200
slot 5  q.i(JsonObj,S)  = func#56 ──> func#30 , func#94 , func#97 , func#99
slot 8  q.c(String)     = func#59 ──> func#30  AES-128-CBC(key=0,iv=0)+hex
slot 12 q.m()           = func#63 ──> func#30
                                     └── RESPONSE DECRYPTION ──────────────────────────┘
slot 4  q.n(String)     = func#55 ──> func#94  AES-ECB decrypt (exact inverse of #85)
slot 16 q.p(Resp,Order,IA)=func#67──> func#30 , func#85 , func#226 ──> func#245 , func#99 ,
                                      func#85 , func#98 ; func#225 maps-integrity
slot 19 q.q(Response)   = func#70 ──> func#247 ──> func#166 (order_stamp2 timestamp),
                                      DeviceModel setHash_key/setNonce/setHash_type (§2.4)
                                     └── TLS / PINNING ──────────────────────────────────┐
slot 20 q.k(String,Z)   = func#71 ──> func#253 CertificatePinner$Builder.<init>+add
                                   └─> func#254 OkHttpClient$Builder.certificatePinner
                                      + Retrofit$Builder.baseUrl/client
slot 21 q.l(I)          = func#72 ──> func#254  (same, without #253)
                                     └── APK SIGNATURE ──────────────────────────────────┐
slot 0  q.j()→long      = func#51 ──> func#73  ──> SHA-256 over PackageInfo.signatures
slot 6  q.v(JsonObject) = func#57 ──> func#73       + literal key "0123456789abcdef"
slot 16 q.p(...)        = func#67 ──> func#226 ──> func#245 ──> pin blob @0x15084
                                                (the only referrer of 0x15084)
                                        func#252 ──> func#36 (hex-decrypt helper)

func#157 ──> func#193 ×2  (XOR-0x5A decode KEY @0x17428, IV @0x17448)
         ──> func#176 (ctx ctor) ──> func#177 (update) ──> func#191 (core) ──> func#178 (final)
func#158 ──> func#193   (XOR-0x5A decode IV2 @0x17458)  ──> same #176/#177/#178 chain
```

### 4.2 ★ The hardcoded key/IV pair — **fully decoded** (supersedes revision 1)

Revision 1 reported the 48 bytes at `.rodata:0x17428`/`0x17448` as *"raw binary key material,
no single-byte XOR decode"*. **That was wrong.** They are XOR-`0x5A` encoded, and the decoder
is `func#193`. Both facts are now proven two independent ways.

#### 4.2.1 `func#193 @ 0x14193c` is an XOR decoder, not a `memcpy`

The core loop (`0x141ccc`) is 6 instructions wrapped in MBA:

```asm
0x141cc4: mov   w23, #0x3a            ; A = 0x3A
0x141cc8: mov   w24, #-0x3b           ; B = ~0x3A = 0xC5
0x141ccc: ldrb  w8, [x21]             ; c = src[i]
0x141cd0: bic   w9, w23, w8           ; w9 = 0x3A & ~c
0x141cd4: and   w8, w8, w24           ; w8 = c & ~0x3A
0x141cd8: orr   w8, w9, w8            ; w8 = (0x3A & ~c) | (c & ~0x3A) = 0x3A ^ c     <-- MBA XOR
0x141cdc: eor   w1, w8, #0x60         ; w1 = (0x3A ^ c) ^ 0x60 = c ^ 0x5A             <-- second XOR
0x141ce0: mov   x0, x19               ; x0 = dst std::string*
0x141ce4: bl    #0x194da8             ; std::string::push_back(dst, w1)   (libc++ SSO, cap 22)
0x141ce8: add   x22, x22, #1          ; i++
0x141cec: subs  x20, x20, #1          ; n--
0x141cf0: add   x21, x21, #1          ; src++
0x141cf4: b.ne  #0x141ccc
```

`(0x3A & ~c) | (c & ~0x3A)` is the textbook MBA expansion of `0x3A ^ c`; the trailing
`eor #0x60` folds in the second constant, so the **net key is `0x3A ^ 0x60 = 0x5A`** —
the *same* key already used by the root-detection and anti-hook blobs (§5.1). One key, whole binary.

**Signature (verified by emulation):**

```c
char *xor5a_decode(char *src, size_t len, std::string *dst /*x8 sret*/);
```

Emulated calls — output matched the hand-computed XOR byte-for-byte:

| call | returns |
|---|---|
| `xor5a_decode(0x17428, 32, …)` | `At91IxVnRSbFppV0UxNFdUSnplTW5ONA` |
| `xor5a_decode(0x17448, 16, …)` | `WMVEwVG02eGFlVmR` |
| `xor5a_decode(0x17458, 16, …)` | `M0VEwVGt0aVJuQjF` |
| `xor5a_decode(0x17307, 32, …)` | `\xca\xa4\xa0\x92…` (binary — *not* XOR-0x5A material) |

#### 4.2.2 The recovered secret

```
.rodata:0x17428  ciphertext (32 B)
  1b 2e 63 6b 13 22 0c 34 08 09 38 1c 2a 2a 0c 6a
  0f 22 14 1c 3e 0f 09 34 2a 36 0e 0d 6f 15 14 1b
        │  XOR 0x5A
        ▼
  "At91IxVnRSbFppV0UxNFdUSnplTW5ONA"          32 ASCII chars, valid Base64
        │  Base64-decode
        ▼
  02 df 75 23 15 67 45 26 c5 a6 95 74 53 13 45 75
  44 a7 a6 54 d6 e4 e3 40                          24 bytes  ==>  AES-192 key

.rodata:0x17448  ciphertext (16 B)
  0d 17 0c 1f 2d 0c 1d 6a 68 3f 1d 1c 36 0c 37 08
        │  XOR 0x5A
        ▼
  "WMVEwVG02eGFlVmR"                            16 ASCII chars, valid Base64
        │  Base64-decode
        ▼
  58 c5 44 c1 51 b4 d9 e1 85 95 59 91               12 bytes  ==>  AES-GCM 96-bit nonce

.rodata:0x17458  (second nonce, used by func#158 — the decrypt direction)
        │  XOR 0x5A
        ▼
  "M0VEwVGt0aVJuQjF"  ->  33 45 44 c1 51 ad d1 a5 49 b9 08 c5   12 bytes
```

So the encoding is **three layers**: `XOR 0x5A` → `Base64 text` → `raw key bytes`.
Revision 1 called this "AES-256 + 128-bit IV"; the true sizes are **192-bit key + 96-bit nonce**.

The **12-byte nonce** is the decisive detail: 12 bytes is *only* meaningful for **AES-GCM**
(the recommended 96-bit IV). It is not a valid CBC/CTR/CFB IV. This matches the Java layer,
which contains the literal transformation string **`AES/GCM/NoPadding`**.

> **Caveat, stated honestly.** Under emulation `func#157`/`func#158` produce all-zero output
> (§11.6). The key/IV are provably decoded and provably stored, and the sizes prove GCM,
> but the `func#191` core would not execute outside a live `JNIEnv`. The *proven* traffic
> ciphers are `func#85/#94` and `func#30` (§11.2, §11.3).

#### 4.2.3 `func#86 @ 0x10de0c` — the request/response key getter

Executed directly:

```
func#86()  ->  "5VEJK9Uk4d0elpVT"
             Base64-decode ->  e5 51 09 2b d5 24 e1 dd 1e 96 95 53      12 bytes
```

`func#86` ignores its arguments and returns a **constant 16-character Base64 string**
whose decode is **12 bytes** — again a GCM-sized key/nonce. It is called by `func#54` and
`func#55`, i.e. by JNI natives **slot 2** `q.o` `(Ljava/lang/String;)Ljava/lang/String;` and
**slot 1** `q.n` `(Ljava/lang/String;)Ljava/lang/String;` — the app's *response-decrypt* and
*request-encrypt* primitives respectively.

Note that `func#86`'s `.rodata` reference (`0x17307`) does **not** decode under XOR 0x5A;
the returned string lives elsewhere in plaintext. `0x17307` is consumed by an inner
opaque-predicate path (`func#90`), not by the key itself.

#### 4.2.4 The full 12-byte-Base64 key family

Every 16-char Base64 literal in `.rodata` decodes to exactly 12 bytes. These are the
GCM nonces/keys the app rotates between:

| Address | Base64 literal | → 12 bytes | Used by |
|---|---|---|---|
| *(runtime const)* | `5VEJK9Uk4d0elpVT` | `e551092bd524e1dd1e969553` | `func#86` → `#54`/`#55` (req/resp) |
| *(runtime const)* | `OVmx02wMFR6WaGtW` | `3959b1d36c0c151e96686b56` | `func#159` |
| *(runtime const)* | `V0V4V2pOa1ptZGsl` | `574578576a4e6b5a6d646b25` | `func#160` |
| *(runtime const)* | `xV2xKTlZsBUVk1He` | `c55db1293959b015159351de` | `func#161` (blob `0x17250`) |
| `0x17448` | `WMVEwVG02eGFlVmR` | `58c544c151b4d9e185955991` | `func#157` (encrypt nonce) |
| `0x17458` | `M0VEwVGt0aVJuQjF` | `334544c151add1a549b908c5` | `func#158` (decrypt nonce) |
| `0x1606a` | `U0dKR01FNW9OV3h3` | → `SGJGME5oNWxw` → `HbF0Nh5lp` (2 layers) | `func#30` |
| `0x16b60` | `WXpKV2JHSnBPRDA9` | → `YzJWbGJpOD0=` → `c2Vlbi8=` → **`seen/`** (3 layers) | `func#218` |

`func#159`, `func#160`, `func#161` were executed and return their constant **regardless of
arguments** — they are pure key/nonce getters.

#### 4.2A ★★ The literal AES key in plaintext: `0123456789abcdef`

The single most damaging finding. A 16-character ASCII string that is *simultaneously*
a valid Base64 body and a textbook AES-128 key sits **unencoded** in `.rodata` twice:

```
.rodata:0x161ca   30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66 00   "0123456789abcdef"
.rodata:0x17ae0   30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66 00   "0123456789abcdef"
```

**Referenced by:**

| Function | Role | Why it needs an AES key |
|---|---|---|
| `func#226` (46,008 B) | APK-signature verifier | references `digest`, `signatures`, `sign`, `MessageDigest`, `SHA-256`, `getInstance`, `order_stamp2` **and** `0123456789abcdef` — it encrypts/HMACs the signature digest before comparing |
| `func#73` (18,052 B) | second signature verifier | same string set |
| `func#71` (12,624 B) | `OkHttpClient$Builder` + `certificatePinner` | read/write timeouts in `SECONDS`, then pins |
| `func#72` (10,016 B) | `Retrofit$Builder.baseUrl` + `client` | the app's HTTP client factory |

Because the app's own HTTP client is built in `func#71`/`func#72` and the tamper check in
`func#226`/`func#73` both use this key, **the same 16 bytes protect TLS pinning, APK integrity
and (via `func#85`) payload encryption.** Recovering it requires no cryptanalysis — it is a
`grep`.

```bash
strings -a -t x lib/arm64-v8a/libtopfollow.so | grep -E '^[[:space:]]*1(61ca|7ae0)'
#  161ca 0123456789abcdef
#  17ae0 0123456789abcdef
```
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
| `func#204` | `0x148bf4` | **16,312** | **SHA-256 pipeline** | `#60`, `#61` (JNI slots 9 and 10 — see the corrected map in §2.2) |
| `func#211` | `0x1500bc` | 2,320 | hex/base64 formatting of digest | `#204` |
| `func#245` | `0x16bbdc` | 2,076 | **pin hash SHA-256** (holds the cert-pin blob `0x15084`) | `#226` |

**Java-side SHA-256:** `func#73` (called by JNI slots 0 and 6) and `func#226` (called by JNI slot 16) both do
`FindClass("java/security/MessageDigest")` → `GetInstance("SHA-256")` → `digest(byte[])`.
So SHA-256 is available **twice** — native LibTomCrypt *and* JNI-upcalled `MessageDigest`. The JNI path is used for the **APK signature digest** (see §3-detection 3.6) and the **certificate pin**.

### 4.3A SHA-1 — also present (revision 1 said it was absent; it is not)

SHA-1 is implemented natively as a hand-rolled, CFF-flattened triple:

| Function | Address | Size | Role | Evidence |
|---|---|---|---|---|
| `func#201` | — | — | **SHA-1 round function** | contains **rotate-right 27**, the `Ch`/`Sigma1` rotation of SHA-1's `f` for rounds 40–59 |
| `func#199` | `0x144d84` | 4,612 | **SHA-1 update** | calls `#201`, `#41`, `#76`; 38 × `bic`, 4 × `lsl #5` (the SHA-1 `rotl5`) |
| `func#202` | `0x1484d0` | 604 | padding/length helper | |

The SHA-1 initial chaining values (`67452301 efcdab89 98badcfe 10325476 c3d2e1f0`) appear as
**blinded constant materialisations** (`mov`+`movk` pairs) rather than a `.rodata` table — which
is why the revision-1 constant sweep missed them. `func#199` is reached from JNI **slot 6**
`q.v` (`func#57`), i.e. SHA-1 is on the request-signing path.

`lsl #5` occurring exactly 4× inside `func#199` is the decisive fingerprint: SHA-1's
`rotl(a,5)` is the only 5-bit left shift in any SHA-2 family member.

**No** MD5, SHA-224, SHA-384 or SHA-512 constants exist anywhere (both endiannesses swept,
plus a low-multiplicity filter over all 5,299 blinded constants — see §10).

### 4.4 Base64

| Item | Address | Detail |
|---|---|---|
| Alphabet (canonical, plaintext) | `0x1501a` | `ABC…XYZabc…xyz0123456789+/` — **standard**, verified byte-for-byte |
| Alphabet (**second copy, RAW**) | `0x17327` | 64 bytes, stored **in plaintext, not XOR-encoded**: `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`. A length prefix `0x41 0x6b 0x3f` (65,107,63) sits at `0x17324`. Used by `func#170`. |
| Global Base64 context | `0x1c0320` (`.data`) | |
| Pointer table | `0x1b6160` (`.data.rel.ro`) | 2,194 qwords, all `R_AARCH64_RELATIVE` |
| `func#26` | `0x03896c` | 68 B — **alphabet installer**: `add x1,x1,#0x1a → 0x1501a; bl func#17 (strlen); add x19,x19,#0x320 → 0x1c0320`. No callers (reached indirectly). |
| `func#796` | `0x19c864` | 8,144 B — the Base64 encode/decode engine (16 data refs into `.rodata`) |
| `func#17` | `0x035f58` | `strlen`-based setup helper |

**Two independent Base64 engines** exist: the `func#26`/`func#796` pair (alphabet `0x1501a`) and
the `func#170` path (alphabet `0x17327`). Both alphabets are the **canonical** RFC 4648 table —
the apparent "custom permutation" seen in raw dumps was a mis-read.

Base64 in this library is used in **two very different ways**, and the distinction matters:

1. **As obfuscation** — up to **4 nested layers** to hide URLs, class names and detection tokens (§4.6, §5.2).
2. **As the transport encoding for key material** — the AES key/nonces are stored as
   *Base64 text* which is itself *XOR-0x5A encoded*. Decoding requires
   `XOR 0x5A` → `Base64-decode` → raw key bytes (§4.2.2). Every one of the eight
   16-character Base64 literals in the binary decodes to exactly **12 bytes**, and the
   32-character one at `0x17428` to exactly **24 bytes** — sizes that are not coincidental
   (GCM nonce / AES-192 key).

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

All recovered by unwinding nested Base64 in `.rodata`; the "refs" column is the function that
holds the `adrp`/`add` to the literal.

```
https://i.instagram.com/api/v2/            3-layer b64 @0x159ec   refs: func#244
https://www.instagram.com/graphql/query    3-layer b64 @0x15de3   refs: func#64, #242, #796, #799, #851
https://www.instagram.com/                 2-layer b64 @0x15c02   refs: func#67, #255
https://                                   4-layer b64 @0x14eae   refs: func#67
create_note/v2/                            3-layer b64 @0x14bf4   refs: func#63, #217
seen/                                      3-layer b64 @0x16b60   refs: func#218
/save/                                     2-layer b64 @0x14de8   refs: func#66, #67, #219, #796, #799
```

The getter functions are one-string-each thunks, which makes the mapping unambiguous:

| Getter | Literal | Decodes to |
|---|---|---|
| `func#242` | `WVVoU01HTklUVFpNZVRrelpETmpkV0ZYTlhwa1IwWnVZMjFHZEV4…` | `https://www.instagram.com/graphql/query` |
| `func#244` | `WVVoU01HTklUVFpNZVRsd1RHMXNkV016VW1oYU0wcG9ZbE0xYW1J…` | `https://i.instagram.com/api/v2/` |
| `func#245` | `WkRnME5UVTVNV1V3T0RZd016TmhPVEF6Tldaa05tSTJObU16WXpO…` | **the certificate pin** (§6.6) |
| `func#255` | `YUhSMGNITTZMeTkzZDNjdWFXNXpkR0ZuY21GdExtTnZiUzg9` | `https://www.instagram.com/` |
| `func#217` | `V1ROS2JGbFlVbXhZTWpWMlpFZFZkbVJxU1hZPQ==` | `create_note/v2/` |
| `func#218` | `WXpKV2JHSnBPRDA9` | `seen/` |
| `func#219` | `TDNOaGRtVXY=` | `/save/` |

The Java layer supplies the remaining ~65 Instagram private-API paths (`feed/timeline/`,
`direct_v2/inbox/`, `media/configure/`, `bloks/…send_login_request/`, …) — see
`work/analysis/dex_protocol.txt`. The native side only hides the **hosts and base paths**.

### 4.7 What is **not** present

> **SHA-1 was on this list in revision 1. That was wrong — SHA-1 *is* present**
> (`func#201` round function, `func#199` update, `func#202` wrapper). See §4.3A and §10 item 21.

| Absent | How it was ruled out |
|---|---|
| MD5 | no `67452301`/`efcdab89` pair with MD5's `0x10325476`+`0x98badcfe` ordering *and* MD5's `T[64]` sine table; blind-constant sweep (low multiplicity ≤3) found nothing |
| SHA-224 / SHA-384 / SHA-512 | IVs absent from `.rodata` and from blinded constants |
| RC4 | no 256-entry identity permutation, no 256-iteration KSA loop, no byte-swap in the cipher core `func#191` |
| ChaCha / Salsa | `0x61707865 0x3320646e 0x79622d32 0x6b206574` absent (both endiannesses, and as `mov`+`movk` pairs) |
| TEA / XTEA | `0x9e3779b9` occurs only as a **CFF dispatcher state** inside `func#201`, not as a delta |
| Blowfish | no `0x243f6a88` P-array, no 4×1024-byte S-boxes |
| RSA / ECC / DSA (native) | no big-number routines. `RSA/ECB/PKCS1PADDING` exists **only in the DEX** — Instagram's own password encryption, done in Java |
| HMAC (RFC 2104) | no `0x36`/`0x5c` ipad/opad block construction. The `sign`/`digest` fields are a hand-rolled SHA-256 concatenation |
| TLS / X.509 parsing | pinning is delegated to OkHttp `CertificatePinner` via JNI (`func#253`) |
| Custom Base64 alphabet | both alphabets are canonical (§4.4) |

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

Mechanism: decrypt the blob with the MBA XOR (`bic/bic/orr`, key `0x5A` inlined at the call site), then read `/proc/self/maps` through the reader helper `func#198 @0x143694` — `__open_2` + `__read_chk`/`read` + `close` (FORTIFY-hardened variants; **there is no `fopen`, no `fgets` and no `strstr` in this library's 88-symbol import table**, see §10 item 39) — split the buffer into lines itself and compare each token inline. Each of the 8 framework tokens is addressed **by its own `adrp`/`add`** — there are no delimiters in the blob, so the lengths are implicit in the gap between consecutive refs. Any hit ⇒ the environment is considered compromised.

### 6.2 Anti-Frida — `func#99 @ 0x115770` (6,752 B, 1,688 insns)

Called by `func#56` (JNI slot 5), `func#57` (JNI slot 6) **and `func#226` (the signature verifier / pinner)** — i.e. Frida is checked right before TLS pins are applied.
Refs `0x17365`, `0x17370`, `0x1737f` inside the XOR-0x37 blob at `0x17365` (41 bytes, no guard bytes):

```
gum-js-loop          @ idx 0   len 11   (Frida's JS event-loop thread name)
libfrida-gadget      @ idx 11  len 15   (embedded gadget .so)
re.frida.server      @ idx 26  len 15   (frida-server process/package name)
```

`func#162 @ 0x136cb8` (callers `#57`, `#65`) additionally Base64-decodes the plaintext-B64 copies `frida` (`0x15be1`), `libfrida-gadget` (`0x16d97`), `re.frida.server` (`0x1607f`), `gum-js-loop` (`0x161eb`) and `/proc/self/maps` (`0x15db5`) — a **second, redundant** Frida path using a *different* encoding of the same tokens. Both must be neutralised.

> Note: there is **no** plaintext `frida` string anywhere in the file. The only `Frid…` match in the whole binary is `Friday` at `0x15e68` (libc++ `time_put` weekday table). Anyone grepping for `frida` finds nothing.

### 6.3 Root detection — `func#169 @ 0x13ba30` (576 B, 144 insns)

Called by `func#154 @ 0x12a068`, whose only caller is `func#57` — i.e. the root check reaches
Java only through **JNI slot 6, `q.v(JsonObject)`** (§2.2A); it is *not* a JNI native itself.
`func#169` is the **only** caller of the `access@PLT` stub (`0x13bac4`).

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

Called by `func#67` (JNI slot 16, the response processor) and by nobody else. References **four** independent Base64 markers:

| Address | Decoded | What it detects |
|---|---|---|
| `0x15db5` | `/proc/self/maps` | the file to scan |
| `0x16336` | `rwxp` | **writable+executable mappings** ⇒ runtime code injection / JIT-based hookers |
| `0x16b75` | `libart.so (deleted)` | ART replaced/patched in place |
| `0x16f69` | `libc.so (deleted)` | libc replaced (typical of Substrate/Riru preload) |

`(deleted)` in a maps path means the inode was unlinked while mapped — the signature of an in-place patched system library.

### 6.5 APK signature / installer verification — `func#73 @ 0x103ad8` (18,052 B, 4,513 insns) & `func#226 @ 0x159c10` (46,008 B, 11,502 insns)

Both reference the identical JNI-reflection string cluster. **Every address below was
re-read from the file byte-for-byte for revision 3**; revision 2's version of this table
contained five wrong addresses (§10 item 32):

| Address | String | Role |
|---|---|---|
| `0x1533e` | `getContext` | |
| `0x15b8b` | `com/nivaroid/topfollow/application/G` | **the app's context singleton** |
| `0x15bb0` | `()Lcom/nivaroid/topfollow/application/G;` | |
| `0x17066` | `()Landroid/content/Context;` | |
| `0x151e6` | `getPackageName` | |
| `0x157df` | `getPackageManager` | |
| `0x16885` | `()Landroid/content/pm/PackageManager;` | |
| `0x15349` | `getPackageInfo` | |
| `0x15eda` | `(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;` | |
| `0x14e80` | `signatures` | field read off `PackageInfo` |
| `0x15f83` | `[Landroid/content/pm/Signature;` | |
| `0x15fa3` | `toByteArray` | |
| `0x15358` | `()[B` | |
| `0x16629` | `java/security/MessageDigest` | |
| `0x1678e` | `getInstance` | |
| `0x1640a` | `(Ljava/lang/String;)Ljava/security/MessageDigest;` | |
| `0x16645` | `SHA-256` | |
| `0x14b88` | `digest` | |
| `0x14cc4` | `([B)[B` | |
| `0x161ca` | **`0123456789abcdef`** | the plaintext AES-128 key (§4.2A) |

The Context is **not** passed in from Java — it is fetched from the static singleton
`com.nivaroid.topfollow.application.G` (`G.getInstance() → getContext()`), which is exactly
what `MyApp.onCreate()` populates:

```java
// MyApp.onCreate(), decompiled from classes.dex
super.onCreate();
G.getInstance().a = this;          // iput-object into G->a:Lcom/.../MyApp;
```

`func#226` additionally references `order_stamp2 @0x1648d`, `sign @0x14ecf` and `'#' @0x14e90`,
i.e. it does more than verify — it also stamps and signs (§7.11).

Reconstructed logic (see the fuller pseudocode in §7.11):

```java
PackageInfo pi = ctx.getPackageManager()
                    .getPackageInfo(ctx.getPackageName(), GET_SIGNATURES);   // flag 0x40
for (Signature s : pi.signatures) {
    byte[] d = MessageDigest.getInstance("SHA-256").digest(s.toByteArray());
    // compare hex-lower(d) against the pinned value decoded from 0x15084
}
```

#### 6.5A The pin blob at `0x15084` — exact encoding, byte-verified

120 bytes of **plaintext ASCII Base64** (unlike nearly every other secret here, it carries
**no** XOR-`0x5A` layer) followed by a NUL:

```
WkRnME5UVTVNV1V3T0RZd016TmhPVEF6Tldaa05tSTJObU16WXpOa056TmhZVE16WVdZNU1E
YzVOR1EyWWprNE5tVTJORGMzT1dWbFlUWmlaV00xWlE9PQ==
```

| Step | Result | Length |
|---|---|---|
| as stored | the blob above | 120 ch |
| Base64-decode ×1 | `ZDg0NTU5MWUwODYwMzNhOTAzNWZkNmI2NmMzYzNkNzNhYTMzYWY5MDc5NGQ2Yjk4NmU2NDc3OWVlYTZiZWM1ZQ==` | 88 ch |
| Base64-decode ×2 | `d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e` | 64 ch |

So it is **two** Base64 layers over a lowercase hex digest (revision 2 said three — §10 item 29).

#### 6.5B What that digest *is* — the APK's own signing certificate

Extracting the signer certificate from this APK's v2 Signing Block and hashing it:

```
DER size              : 864 bytes
SHA-256(DER)          : d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e
SHA-1(DER)            : d6dd5ad1a3e314637a8617cbcf3eb2db8ba6c63f
MD5(DER)              : 8883fa259930537ea2dc867d814b71c9
Subject == Issuer     : CN=Maryam Ahmadi, OU=Android Developer, O=NivaRoid,
                        L=Shiraz, ST=Fars, C=IR
Serial                : 1        Signature alg: sha256WithRSAEncryption
Validity (UTC)        : 2023-12-15T17:44:33Z .. 2048-12-08T17:44:33Z
Public key            : RSA, 2048-bit, SPKI DER = 294 bytes
```

**`SHA-256(DER) == the decoded pin, exactly.** This is not an inference: `frida/clone_signer.py`
re-reads both the APK and `libtopfollow.so` and asserts the equality on every run, and
`rpc.exports.signature()` in `frida/topfollow_agent.js` recomputes it live on the device
(with a from-scratch JS SHA-256) and compares against the blob read out of the mapped
module. Both report a match.

The blob is stored **in the clear**, so it costs nothing to recover; and because it pins a
*value that the app itself carries around in its own APK*, the check is trivially forgeable
from Java (below).

**Consequence for §6.6 (TLS pinning) — and a retraction.** The only pin-shaped constant
anywhere in this library is the `0x15084` blob, and it decodes to the **APK signer
certificate's** SHA-256 — not to an Instagram leaf or SPKI digest. Re-encoding those 32 raw
bytes the way OkHttp expects would give

```
base64(bytes.fromhex("d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e"))
    == "2EVZHghgM6kDX9a2bDw9c6ozr5B5TWuYbmR3nupr7F4="
    -> pin string "sha256/2EVZHghgM6kDX9a2bDw9c6ozr5B5TWuYbmR3nupr7F4="
```

**but that string does not occur in `libtopfollow.so`** — searched plain *and* XOR-`0x5A`,
also for a bare `sha256` and for any 43-char Base64 ending in `=`. The only `sha256/` text in
the whole APK is OkHttp's own `CertificatePinner` validation message
(`"+pins must start with 'sha256/' or 'sha1/': "`) in `classes.dex`. And `0x15084` has
**exactly one referrer in the entire library: `func#245`** — neither `func#253` nor `func#254`
nor `func#71`/`func#72` references it.

So revision 2's claim that `func#253` "adds `sha256/d845591e…` for the Instagram hosts" is
**withdrawn** (§10 item 30). What is provable statically is only that `func#253` calls
`okhttp3/CertificatePinner$Builder.<init>(String, String[])` and `.add(String, String[])` and
`func#254` calls `OkHttpClient$Builder.certificatePinner(...)`. The pin **values** are not
string constants in the `.so`; they arrive as arguments (from `func#57`/`func#71`/`func#72`,
i.e. from Java `JsonObject`s and the server-issued `DeviceModel` of §2.4) or are built at
runtime. Capturing `CertificatePinner.Builder.add(...)` live — which
`frida/topfollow_agent.js` §7.2 logs, while neutralising it — is what settles it. Until then:
**pinning exists, its values are unknown.**

#### 6.5C Why a repackaged APK fails, and the clean way to make it pass

`func#245 @ 0x16bbdc` (2,076 B) is the dedicated pin-hash routine and its **only** caller is
`func#226`. A re-signed / repackaged APK therefore fails, and because `func#226` also drives
the AES layer (`func#85`) and the timing check (`func#98`), failure **poisons the crypto path
rather than throwing a clean error** — you get wrong bytes, not an exception.

Three ways to defeat it, in order of preference:

1. **Forge the input on the Java side (recommended, implemented).** The native code never
   reads the APK itself — it asks `PackageManager`. So return the *original* certificate:

   ```js
   // frida/topfollow_agent.js §7.4 — this is what it does
   const PM = Java.use('android.app.ApplicationPackageManager');
   PM.getPackageInfo.overloads.forEach(ov => {
     ov.implementation = function () {
       const pi = ov.apply(this, arguments);
       const flags = arguments[1] | 0;
       if (pi && (flags & 0x40)) {                    // GET_SIGNATURES
         const Sig = Java.use('android.content.pm.Signature');
         pi.signatures.value = Java.array('android.content.pm.Signature',
                                          [Sig.$new(ORIGINAL_CERT_DER_BYTES)]);
       }
       return pi;
     };
   });
   // plus Signature.toByteArray() -> ORIGINAL_CERT_DER_BYTES as a second net,
   // plus SigningInfo for API 28+ (GET_SIGNING_CERTIFICATES = 0x08000000)
   ```

   `func#226`'s own `MessageDigest("SHA-256")` then produces the pinned digest and the
   comparison succeeds. Nothing in the library is written to, so no opaque predicate can
   flip and no `b .` trap (§3.8) can fire.

2. **Never let it run.** `func#73` is called only by `func#51` (JNI slot 0, `q.j()`) and
   `func#57` (slot 6, `q.v`); `func#226` only by `func#67` (slot 16, `q.p`). Those three
   Java entry points are the complete trigger set (§2.2A).

3. **Do *not* try to force-return `func#226`/`func#73`.** Both are control-flow flattened
   with reachable `b .` traps, and the polarity of their result is unproven — §8 item 7.
   `frida/topfollow_agent.js` therefore leaves them in watch-only mode by default
   (`stubDetection: false`).

`frida/clone_signer.py` additionally rebuilds a **byte-identical-structure** certificate
(same version/serial/DN/validity/algorithm, fresh RSA-2048 key) so that a repackaged APK can
be signed with a v1 (JAR) signature carrying the same *shape* of certificate. That is
belt-and-braces only: on Android 7+ `PackageManager` sources signatures from the v2/v3
Signing Block, so option 1 is what actually makes the check pass.

### 6.6 TLS certificate pinning — `func#253 @ 0x172460`, `func#254 @ 0x173c40`, `func#71/#72`

Verified `data_refs` (revision 3, re-read from the file):

| Referrer | Address | String |
|---|---|---|
| `func#253` | `0x15113` | `okhttp3/CertificatePinner$Builder` |
| `func#253` | `0x1536c` | `(Ljava/lang/String;[Ljava/lang/String;)Lokhttp3/CertificatePinner$Builder;` |
| `func#253` | `0x1649a` | **`add`** *(revision 2 printed `0x1649e`, which is `certificatePinner`)* |
| `func#253` | `0x16a7e` | `()Lokhttp3/CertificatePinner;` |
| `func#253` | `0x1535d` / `0x14e24` | `<init>` / `build` |
| `func#254` | `0x1585a` | `retrofit2/Retrofit$Builder` |
| `func#254` | `0x15135` | `(Lokhttp3/OkHttpClient;)Lretrofit2/Retrofit$Builder;` |
| `func#254` | `0x153b7` / `0x15f1f` | `baseUrl` / `client` |
| `func#254` | `0x16e16` | `(Ljava/lang/String;)Lretrofit2/Retrofit$Builder;` |
| `func#71`,`func#72` | `0x16240` | `(Lokhttp3/CertificatePinner;)Lokhttp3/OkHttpClient$Builder;` |
| `func#71`,`func#72` | `0x1649e` | `certificatePinner` |
| `func#71`,`func#72` | `0x167d8` | `okhttp3/OkHttpClient$Builder` |
| `func#71`,`func#72` | `0x15a4a` / `0x1633f` / `0x16813` / `0x16670` | `readTimeout` / `writeTimeout` / `SECONDS` / `Ljava/util/concurrent/TimeUnit;` |
| `func#71`,`func#72` | `0x15e4b` | `()Lokhttp3/OkHttpClient;` |
| `func#71`,`func#72` | `0x14ee5` | `(JLjava/util/concurrent/TimeUnit;)Lokhttp3/OkHttpClient$Builder;` *(revision 2 called this `nonce` — it is the timeout signature; the real `nonce` strings are at `0x151f5` and `0x15a43`)* |

Chain, from the direct-call edges: **`func#71` (JNI slot 20, `q.k(String,Z)`) → `func#253`
**and** → `func#254`; `func#72` (JNI slot 21, `q.l(I)`) → `func#254` only.** `func#253` is
called by nobody else, `func#254` by nobody else. So the pinned client is built from exactly
two Java entry points, both of which take the base URL / config as an argument.

This defeats Burp/mitmproxy/Charles out of the box **if** real pins are supplied; you must
hook `CertificatePinner.Builder.add` (to register zero pins) and `CertificatePinner.check`
**and** survive `func#99`'s Frida scan, which `func#226` runs immediately before pinning
(§6.5). `frida/topfollow_agent.js` §7.2/§7.3 does all three and logs the pin arguments it
sees, which is how the unknown values get recovered.

### 6.7 Timing / anti-debug — `func#98 @ 0x114fbc`

The **only** caller of `clock@PLT` (`0x114ff0`). Called by **13 functions**: `func#56`, `#57`, `#58`, `#59`, `#60`, `#61`, `#62`, `#63`, `#64`, `#65`, `#67` (eleven of the 22 JNI natives — see §2.2A), plus `func#154` and `func#226` (signature verifier / pinner). Pattern: `t0 = clock(); <work>; t1 = clock(); if (t1 - t0 > threshold) ⇒ traced`.

### 6.8 Device fingerprinting

| Function | Address | Fields read |
|---|---|---|
| `func#64` (JNI slot 13, `q.b()`) | `0x0cbeac` | `Build.*` — `BRAND @0x16c1a`, `DEVICE @0x16211`, model/manufacturer family. Note `0x16c10` itself is an **empty string** (`\0`); `" expression"` is at `0x16c00`, `"eHBvc2Vk"` at `0x16c11`, `"BRAND"` at `0x16c1a`, `"hash_type"` at `0x16c21` — this whole run is packed ASCII `.rodata`, not a table (§10 item 25). |
| `func#97` | `0x113cd0` | `android/provider/Settings$Secure @0x1643c`, `ANDROID_ID @0x1645d`, `getString @0x16468`, `getDevice`, `family_device_id @0x1647c` |
| `func#152` | `0x12472c` | `fcm_token @0x159d5`, `token` |
| `func#166` (not a JNI native; called by `func#152` and `func#247`) | `0x13a358` | `order_stamp2 @0x1648d` — monotonic time |
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

### 7.2 The MBA XOR string decryptor — **`func#193 @ 0x14193c`** (executed, not guessed)

Every call site uses the same 3-argument convention:

```c
/* std::string* (sret in x8) xor5a_decode(const char *src /*x0*/, size_t n /*x1*/) */
```

The real decode loop is **9 instructions at `0x141ccc`**, reproduced verbatim from the binary:

```asm
0x141cbc:  cbz      x20, #0x141cf8        ; n == 0 -> skip
0x141cc0:  mov      x22, xzr              ; i = 0
0x141cc4:  mov      w23, #0x3a            ; KEY_A
0x141cc8:  mov      w24, #-0x3b           ; == 0xffffffc5 == ~0x3a   KEY_B = ~KEY_A
0x141ccc:  ldrb     w8,  [x21]            ; c = src[i]
0x141cd0:  bic      w9,  w23, w8          ; KEY_A & ~c
0x141cd4:  and      w8,  w8,  w24         ; c     & ~KEY_A
0x141cd8:  orr      w8,  w9,  w8          ; == KEY_A ^ c              <- MBA identity
0x141cdc:  eor      w1,  w8,  #0x60       ; ^ 0x60
0x141ce0:  mov      x0,  x19              ; &result
0x141ce4:  bl       #0x194da8             ; std::string::push_back(char)
0x141ce8:  add      x22, x22, #1
0x141cec:  subs     x20, x20, #1
0x141cf0:  add      x21, x21, #1
0x141cf4:  b.ne     #0x141ccc
```

The mixed-boolean-arithmetic identity is exact for every byte:

```
(KEY_A & ~c) | (c & ~KEY_A)  ==  KEY_A ^ c           ; KEY_A = 0x3A
(KEY_A ^ c) ^ 0x60           ==  (0x3A ^ 0x60) ^ c   ==  0x5A ^ c
```

So the **effective single-byte key is `0x5A`**, built from two immediates so that no
`0x5A` ever appears in the instruction stream and a naive "search for the XOR key" script
finds nothing.

Equivalent C, and the one-liner used to bulk-decode `.rodata` offline
(`work/analysis/xorcorp2.py`):

```c
static inline uint8_t mba_xor(uint8_t c, uint8_t k) {
    return (uint8_t)((k & (uint8_t)~c) | (c & (uint8_t)~k));   /* == k ^ c */
}
static void xor5a_decode(const uint8_t *src, size_t n, std::string *out) {
    for (size_t i = 0; i < n; i++) out->push_back((char)(0x3A ^ src[i] ^ 0x60));
}
/* Python equivalent: bytes(b ^ 0x5A for b in blob) */
```

Two other MBA forms appear elsewhere in the same function, both used as **opaque
predicates**, not for data:

```asm
; form B — "is c odd?"  (always false for the constants it guards)
0x141e04:  ldrb  w8, [x19]
0x141e10:  eor   w9, w8, #0xfe
0x141e14:  and   w8, w9, w8        ; == c & ~0xFE == c & 1
0x141e18:  tst   w8, #0xff
0x141e1c:  b.eq  ...

; form C — "x*(x-1) is even" (a tautology; always true)
0x141bb8:  ldr   w11, [x22]        ; x = *opaque_global_1  (0x1bb808)
0x141bbc:  ldr   w12, [x23]        ; y = *opaque_global_2  (0x1bb810)
0x141bc8:  sub   w13, w11, #1
0x141bcc:  mul   w11, w13, w11     ; x*(x-1)
0x141bd0:  eor   w13, w11, #0xfffffffe
0x141bd4:  tst   w13, w11
0x141bd8:  cset  w13, ne           ; always 0
0x141bdc:  cset  w14, eq           ; always 1
0x141be0:  cmp   w12, #9
0x141be4:  cset  w15, gt
0x141be8:  cmp   w12, #0xa
0x141bf0:  cset  w12, lt           ; always 1
```

Form C reads two words from the writable globals at `0x1bb808` and `0x1bb810` — these are
**CFF anti-analysis sentinels**, initialised so the predicate is constant. The dispatcher
itself (`0x141aa8`, state register `w14`) compares the state against six
`mov`+`movk`-split 32-bit constants (`0x655a/0x3507655a`, `0x6b73/0xa46b6b73`,
`0x6152/0x4e36152`, `0x655b/0x3507655b`, `0x72ab/0x4dd272ab`), which is why the constants
never appear in `strings` output.

> `func#170 @ 0x13be44`, cited in revision 1, is a *different* MBA-decoding helper with the
> same idiom; `func#193` is the one actually invoked by `func#157`/`func#158`/`func#86` and
> is the one that was executed under emulation.

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

    /* REV 4 CORRECTION — the library imports NO fopen, NO fgets and NO strstr.
       func#200 reaches the file through the reader helper func#198 @0x143694,
       which uses __open_2 + __read_chk/read + close, and the token search is an
       inlined byte loop.  The shape below is therefore the real one. */
    int fd = read_whole_file(&blob[1] /* "/proc/self/maps" */, buf, &len);  // func#198
    if (fd < 0) return false;

    for (size_t off = 0; off + 1 < len; ) {               // own line splitter
        size_t eol = memchr_off(buf, off, len, '\n');
        for (int i = 1; i < 9; i++) {                     // token 0 is the path itself
            char tok[32];
            memcpy(tok, blob + HOOK_TOKENS[i].off, HOOK_TOKENS[i].len);
            tok[HOOK_TOKENS[i].len] = '\0';
            if (contains(buf + off, eol - off, tok)) { close(fd); return true; }
        }
        off = eol + 1;
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

    /* REV 4 CORRECTION — no fopen/fgets/strstr anywhere in the import table.
       func#225 reads through the helper func#129 @0x11deb0
       (__open_2 + __read_chk/read + close) and compares inline. */
    char *buf; size_t len;
    if (read_whole_file(maps, &buf, &len) < 0) return false;   // func#129
    bool bad = false;
    for (size_t off = 0; off + 1 < len; ) {                    // own line splitter
        size_t eol = memchr_off(buf, off, len, '\n');
        size_t n   = eol - off;
        if (contains(buf + off, n, rwxp)) { bad = true; break; }  // RWX mapping => injected code
        if (contains(buf + off, n, art )) { bad = true; break; }  // patched ART
        if (contains(buf + off, n, libc)) { bad = true; break; }  // patched libc
        off = eol + 1;
    }
    free(buf);
    return bad;
}
```

### 7.7 Key/IV installation (`func#157 @ 0x131d58`) — **corrected**

Reconstructed from the de-flattened CFG (`work/analysis/deob/F157.txt`). The two
`bl func#193` sites are the whole point of the prologue:

```c
/* .rodata, XOR-0x5A encoded — NOT raw key bytes */
static const char KEY_CT[32] = {          /* 0x17428 */
    0x1b,0x2e,0x63,0x6b,0x13,0x22,0x0c,0x34,
    0x08,0x09,0x38,0x1c,0x2a,0x2a,0x0c,0x6a,
    0x0f,0x22,0x14,0x1c,0x3e,0x0f,0x09,0x34,
    0x2a,0x36,0x0e,0x0d,0x6f,0x15,0x14,0x1b };
static const char IV_CT[16]  = {          /* 0x17448 */
    0x0d,0x17,0x0c,0x1f,0x2d,0x0c,0x1d,0x6a,
    0x68,0x3f,0x1d,0x1c,0x36,0x0c,0x37,0x08 };

/* after xor5a_decode():
 *   KEY_CT -> "At91IxVnRSbFppV0UxNFdUSnplTW5ONA"  -> b64 -> 24 B  (AES-192)
 *   IV_CT  -> "WMVEwVG02eGFlVmR"                  -> b64 -> 12 B  (GCM nonce)
 */

struct CipherCtx {                 /* 24 bytes; zeroed by func#176 */
    void   *p0, *p1, *p2;          /* key ref, iv ref, state */
};

void func_157(std::string *in /*x0*/, std::string *out /*x8 sret*/) {
    std::string keybuf, ivbuf;                       /* [x29-0x28], [x29-0x40] */

    xor5a_decode(KEY_CT, 32, &keybuf);               /* bl func#193 @0x14193c   */
    xor5a_decode(IV_CT,  16, &ivbuf );               /* bl func#193             */

    func_176(&ctx /*x29-0x58*/, &keybuf, &ivbuf);    /* ctor: 3 stores of 0, then stash */
    func_177(...);                                   /* update -> func#191 core  */
    func_178(...);                                   /* final                    */
    /* ... func#178 reached 3x, func#41 and func#76 are opaque-predicate helpers */
}
```

`func#158 @ 0x133970` is the mirror image and installs the **second nonce** from `0x17458`
(`"M0VEwVGt0aVJuQjF"` → `334544c151add1a549b908c5`).

Both were executed under emulation (§11.6). They decode the key material correctly but the
`func#191` core returns zeros without a live `JNIEnv`, so the *mode* is inferred from the
key/nonce sizes (24 B ⇒ AES-192, 12 B ⇒ GCM) and corroborated by the DEX string
`AES/GCM/NoPadding`.
### 7.8 LibTomCrypt AES key expansion (`func#14 @ 0x32158`) — **layout proven at runtime**

`func#14` is `LibTomCrypt`'s **combined** setup (it derives both directions in one call).
Instrumenting it while running `func#85` gave the exact argument mapping and the exact
`symmetric_key` layout:

```
entry 0x32158 for func#85("hello", "0123456789abcdef"):
    x0 = 0x81efb18   symmetric_key *skey          (caller stack frame)
    x1 = 0x10001021  const unsigned char *userkey (== the std::string SSO buffer)
    x2 = 0x16c10     unused (points at plain ASCII .rodata " expression\0x21\0\0eHBvc2Vk\0BRAND")
    x3 = 0x10        keylen in BYTES   (0x18 for AES-192, 0x20 for AES-256)
    x4 = 0x10        keylen again (the MBA gate tests both w3 and w4)
```

The key-size gate is itself MBA-obfuscated, but reduces to a two-value test:

```asm
0x32178:  mvn   w8, w4
0x3217c:  orr   w8, w8, #8        ; (~w4) | 8
0x32180:  cmn   w8, #0x11         ; == 0x11  <=>  w4 == 16
0x32184:  cset  w8, ne
0x32188:  cmp   w4, #0x20         ; == 32
0x3218c:  cset  w10, ne
0x32190:  eor   w11, w10, w8
0x32194:  orr   w8, w10, w8
0x32198:  eor   w8, w8, #1        ; == 1 only when w4 is 16 or 32
0x321a4:  mvn   w9, w3            ; same test repeated on w3 (24 handled on the other path)
...
0x321f0:  add   x8, x0, #0x3d4    ; &skey->dK  region
0x321f8:  add   x9, x0, #0x418
0x32200:  add   x8, x0, #0x3cc
0x32208:  add   x8, x0, #0x3d0
0x32210:  add   x9, x0, #0x3d8
0x3221c:  add   x8, x0, #0x3f8
```

**Verified `symmetric_key` layout** (all three key sizes, checked against FIPS-197):

```c
struct symmetric_key {            /* 0x258 bytes of the caller frame are used */
    /* +0x00 */ void     *vptr_or_id;
    /* +0x08 */ uint32_t  aux;                 /* reads 1 in the ECB path; not the round count */
    /* +0x0c */ uint32_t  eK[60];              /* round keys, LITTLE-ENDIAN words, STRIDE 32 B */
    /* +0x3cc.. */        dK[60];              /* decrypt schedule, written by func#16 */
};
```

The round key at `+0x0c + 32*r` was found byte-identical to the FIPS-197 expansion, with
each 16-byte row stored as four little-endian `uint32_t` words:

| key | len | round-key rows matched | `func#85("hello", key)` | reference `AES-ECB/PKCS7` |
|---|---|---|---|---|
| `0123456789abcdef` | 16 | 11/11 ✔ | `674c7ef38e78cabd9cec9c125823a639` | identical ✔ |
| `000102…17` (`bytes(range(24))`) | 24 | 13/13 ✔ | `12056740635d5dd4124b24264bb8a00a` | identical ✔ |
| `000102…1f` (`bytes(range(32))`) | 32 | 15/15 ✔ | `91684487c34c3456eb4e901cef884a1e` | identical ✔ |

The `x1` argument was dereferenced at the hook point and contains the key **verbatim** —
`*x1 == b'0123456789abcdef'` — i.e. the key-string bytes are used directly as the AES key with
**no KDF, no hashing, no truncation, no padding**. `x2` was also dereferenced: it points at
`0x16c10`, which is plain ASCII `.rodata` (`" expression\0x21\0\0eHBvc2Vk\0BRAND"`) and is
never read as a table. `x3`/`x4` carry the key length in **bytes** (`0x10 / 0x18 / 0x20`).

Reconstructed source (LibTomCrypt `rijndael_setup`, de-obfuscated):

```c
/* observed prototype: x0=skey, x1=userkey, x2=unused, x3=keylen, x4=keylen */
int rijndael_setup(symmetric_key *skey, const unsigned char *userkey,
                   const void *unused, int keylen, int keylen2) {
    if (keylen != 16 && keylen != 24 && keylen != 32) return CRYPT_INVALID_KEYSIZE;
    int Nr = (keylen == 16) ? 10 : (keylen == 24) ? 12 : 14;   /* local; the struct's
                                                                  +0x08 word reads 1 */
    memcpy(&skey->eK[0], userkey, keylen);

    for (int i = keylen/4, r = 0; i < 4*(Nr + 1); ) {
        uint32_t tmp = skey->eK[i-1];
        if (r == 0) {
            r = 1;
            tmp = (setup_Sbox[(tmp>> 8)&0xff]      ) |
                  (setup_Sbox[(tmp>>16)&0xff] <<  8) |
                  (setup_Sbox[(tmp>>24)&0xff] << 16) |
                  (setup_Sbox[(tmp    )&0xff] << 24);   /* RotWord+SubWord on the LE word */
            tmp ^= setup_rc[r++];                        /* Rcon @0x13b10 */
        } else if (keylen == 32 && r == 1) {
            r = 2;
            tmp = (setup_Sbox[(tmp    )&0xff]      ) |
                  (setup_Sbox[(tmp>> 8)&0xff] <<  8) |
                  (setup_Sbox[(tmp>>16)&0xff] << 16) |
                  (setup_Sbox[(tmp>>24)&0xff] << 24);
        } else r = 0;

        skey->eK[i] = skey->eK[i - keylen/4] ^ tmp;
        i++;
    }
    /* func#14 builds the ENCRYPT schedule only; the decrypt schedule is built
       separately by func#16 @0x35518, which calls func#12 and func#13 */
    return CRYPT_OK;
}
```

Tables used (all in `.rodata`, all byte-verified against FIPS-197 — see §4.1):
`setup_Sbox @0x128b0`, `setup_RSbox @0x139b0`, `setup_rc @0x13b10`,
`Te0-Te3 @0x118b0 / 0x11cb0 / 0x120b0 / 0x124b0`,
`Td0-Td3 @0x129b0 / 0x12db0 / 0x131b0 / 0x135b0`.
There is **no** `setup_log` / `setup_alog` table in this build (searched exhaustively).

Call tree — every edge below comes from `work/analysis/calls.json` and was re-confirmed in the
execution trace of `func#85` / `func#94` / `func#30` / `func#36`:

```
                     ┌── func#14 @0x32158  rijndael_setup   (ENCRYPT key schedule)
 func#85  AES-ECB enc┤── func#15 @0x34424  setup helper ──► func#12 @0x2fdcc ─► func#10 @0x2dc00
                     │                                       ecb_encrypt          Te0..Te3 core
 func#30  AES-128-CBC┤── func#14, func#15, func#17 … (zero-key CBC, hex out)
                     │
                     ┌── func#16 @0x35518  rijndael_setup   (DECRYPT key schedule)
 func#94  AES-ECB dec┤        ├──► func#13 @0x30f18  ──────► func#11 @0x2eb94
                     │        │    ecb_decrypt                Td0..Td3 core
 func#36  AES-256   │        └──► func#12 ─► func#10   (re-encrypts to verify padding)
        AES-dec(hex) │
                     └── func#14
```

Note the **asymmetry**: `func#16` (the decrypt-side setup, 2112 bytes) calls *both*
`func#12` (`ecb_encrypt`) and `func#13` (`ecb_decrypt`). The encrypt-side setup `func#14`
calls neither — it builds the schedule directly. That is why the decrypt half of the library
is heavier: `func#94` is 9140 bytes against `func#85`'s 6556, and `func#13`/`func#11`
(4672 + 4664 bytes) exceed `func#12`/`func#10` (4428 + 3988). Both directions were
round-trip verified under emulation (§11.2), so the exact internal reason does not affect
any conclusion in this report.

### 7.9 The two real ciphers — **reconstructed from execution, not from reading**

#### `func#85 @ 0x10c470` → `std::string aes_ecb_encrypt_hex(std::string pt, std::string key)`

```c
/*  PROVEN by known-answer test against FIPS-197 — see §11.2  */
std::string func_85(const std::string &pt, const std::string &key, int unused) {
    if (pt.empty() || key.empty()) return "null";                 /* literal @0x14e8b */

    size_t keylen = key.size();
    if (keylen != 16 && keylen != 24 && keylen != 32) return "null";   /* AES-128/192/256 */

    symmetric_key skey;
    rijndael_setup(key.data(), keylen, &skey);                    /* func#14, LibTomCrypt */

    size_t n   = pt.size();
    size_t pad = 16 - (n % 16);                                   /* PKCS#7, always >=1 */
    uint8_t *buf = malloc(n + pad);
    memcpy(buf, pt.data(), n);
    memset(buf + n, pad, pad);

    uint8_t ct[n + pad];
    for (size_t i = 0; i < n + pad; i += 16)
        rijndael_ecb_encrypt(buf + i, ct + i, &skey);             /* ECB: no chaining */

    return lowercase_hex(ct, n + pad);                            /* 2 chars per byte */
}
```

`func#94 @ 0x110b70` is the **exact inverse**: it parses the hex string back to bytes and runs
`rijndael_ecb_decrypt` (`func#16` → `func#13` → `func#11`, Td tables). Round-trip verified for
every key size and every plaintext length tested.

Two properties make this trivially attackable:

* **ECB** — equal plaintext blocks produce equal ciphertext blocks. Demonstrated:
  encrypting `"A"*32` yields `3bfd04cc…21383` **twice** in a row; encrypting the
  full 16-byte PKCS#7 pad block always yields `377222e061a924c591cd9c27ea163ed4`
  regardless of what precedes it.
* **Hex, not Base64** — output is exactly 2× the padded length, so ciphertext size leaks
  plaintext size to the byte.

#### `func#30 @ 0x38fa4` → `std::string aes128_cbc_zerkey_hex(std::string pt)`

```c
/*  PROVEN by known-answer test — see §11.3  */
std::string func_30(const std::string &pt, const std::string &ignored_key, int w1) {
    if (pt.empty()) return "null";

    /* the key buffer is allocated and then ZEROED; the key argument is never read */
    uint8_t key[16];  memset(key, 0x00, 16);          /* bl memset@plt, w1 = 0 */
    uint8_t  iv[16];  memset(iv,  0x00, 16);

    symmetric_key skey;
    rijndael_setup(key, 16, &skey);                    /* func#14 */

    size_t n = pt.size(), pad = 16 - (n % 16);
    uint8_t p[n + pad];
    memcpy(p, pt.data(), n);  memset(p + n, pad, pad); /* PKCS#7 */

    uint8_t ct[n + pad], prev[16];  memcpy(prev, iv, 16);
    for (size_t i = 0; i < n + pad; i += 16) {
        uint8_t blk[16];
        for (int j = 0; j < 16; j++) blk[j] = p[i+j] ^ prev[j];
        rijndael_ecb_encrypt(blk, ct + i, &skey);      /* func#12 -> func#10, Te tables */
        memcpy(prev, ct + i, 16);
    }
    memset(key, 0, 16);                                /* 2x memset = key wipe */
    return lowercase_hex(ct, n + pad);
}
```

This is the **worst finding in the library**. `AES-128-CBC` with a **fixed all-zero key** and a
**fixed all-zero IV** is a *keyless* cipher: its output is a pure, publicly-computable function
of the plaintext. It is called by **7 of the 22 JNI natives**, including:

* `func#67` — **JNI slot 16**, `x0015e49c (Lretrofit2/Response;Lcom/nivaroid/topfollow/models/Order;Lcom/nivaroid/topfollow/models/InstagramAccount;)Ljava/lang/String;` = `q.p(…)`, i.e. **the response handler**;
* `func#56` — JNI slot 5, `x00120b1e (Lcom/google/gson/JsonObject;Ljava/lang/String;)V` = `q.i(…)`;
* `func#57` — JNI slot 6, `x0012e5a1 (Lcom/google/gson/JsonObject;)V` = `q.v(…)`, the 160 KB request builder;
* `func#59`, `func#60`, `func#61`, `func#63`.

A fixed IV additionally makes the first ciphertext block a deterministic hash of the first
plaintext block, so an observer can recognise repeated request prefixes without decrypting.

#### `func#36 @ 0x3a838`

Hex-string-in / raw-bytes-out **AES-256-ECB decrypt + PKCS#7 unpad** (revision 4). Its key
argument is ignored — verified over 6 different values — but its key is **not** a fixed internal
constant either: `rijndael_setup` (`func#14`) is entered with `keylen = 32` and a user-key pointer
that lands inside `func#36`'s own stack frame, overlapping a local `std::string`, so the effective
key varies with the input length. It is *not* the inverse of `func#30`. Only caller is `func#252`,
whose only caller is JNI slot 20 `q.k` (`func#71`) — the `OkHttpClient`/`CertificatePinner`
construction path. Because it echoes its input when the padding is invalid and returns the unpadded
plaintext when it is valid, it is a **padding oracle**. Full evidence in §11.11(a).
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

All edges below come from `work/analysis/funcmap.json`'s direct-call graph, keyed by the
corrected slot numbers of §2.2.

```
slot 0   func#51  (1.4 KB) ──> func#73  APK-signature SHA-256        [q.j() -> long]

slot 5   func#56  (47 KB) ─┬─> func#30  AES-128-CBC key=0 iv=0       [q.i(JsonObject,String)]
                           ├─> func#94  AES-ECB decrypt
                           ├─> func#99  anti-frida (gum-js-loop / libfrida-gadget / re.frida.server)
                           ├─> func#97  Settings$Secure.ANDROID_ID
                           └─> func#98  clock() timing

slot 6   func#57  (160 KB) ─┬─> func#200 anti-hook (xposed/lsposed/edxposed/riru/substrate/
 THE HUB                     │            libcso/libbridge/zygisk)   [q.v(JsonObject)]
                           ├─> func#99  anti-frida
                           ├─> func#162 anti-frida (base64 variant)
                           ├─> func#157 AES-192 key + 12 B GCM nonce install  <== hardcoded secret
                           ├─> func#158 second GCM nonce install               <== hardcoded secret
                           ├─> func#154 ─> func#169 root (9× su paths via access())
                           ├─> func#85  AES-ECB encrypt + envelope
                           ├─> func#30  AES-128-CBC keyless
                           ├─> func#73  APK-signature SHA-256
                           ├─> func#97  ANDROID_ID
                           ├─> func#152 / func#153 / func#156  (order / token / 3-arg sign)
                           └─> func#98  clock() timing

slot 9   func#60  (180 KB) ──> func#85, func#30, func#97, func#98    [q.r(JsonObject,String,String)]
slot 10  func#61  (73 KB)  ──> func#30, func#200 anti-hook, func#98  [q.t(JsonObject,IA,Order)]
slot 13  func#64  (35 KB)  ──> func#157 (GCM ctx), func#97, func#98,
                              Build.* fingerprint                    [q.b()]
slot 14  func#65  (15 KB)  ──> func#85, getters #159/#160/#161,
                              func#162 anti-frida-b64, func#98       [q.a(String)]

slot 16  func#67  (118 KB) ─┬─> func#225 maps integrity (rwxp / libart.so (deleted) /
 THE RESPONSE                │            libc.so (deleted))          [q.p(Response,Order,IA)]
 HANDLER                     ├─> func#226 signature + pin (46 KB) ─> func#245 pin hash
                           │       (func#245 is the SOLE referrer of the blob @0x15084)
                           │                                └─> func#99  anti-frida
                           │                                └─> func#85  AES
                           │                                └─> func#98  clock()
                           ├─> func#30  AES-128-CBC keyless
                           ├─> func#244 build https://i.instagram.com/api/v2/ URL
                           └─> inflate() gunzip response body

slot 19  func#70  (3.4 KB) ──> func#247 ─> func#166 order_stamp2 timestamp,
                              DeviceModel.setHash_key/setNonce/setHash_type (§2.4)

slot 20  func#71  (12.6 KB) ─┬─> func#253 CertificatePinner$Builder.<init> + .add
                             └─> func#254 OkHttpClient$Builder.certificatePinner
                                          + Retrofit$Builder.baseUrl/.client    [q.k(String,Z)]
slot 21  func#72  (10 KB)   ──> func#254 only                                   [q.l(I)]
```

**Every large JNI entry point re-runs the checks.** There is no single "isCompromised()" gate to patch; you must neutralise `func#200`, `func#99`, `func#162`, `func#225`, `func#169`, `func#73`/`func#245`, `func#253`/`func#254`, and `func#98` independently.

---

## 8. Weaknesses & practical bypass notes

| # | Finding | Severity | Why it matters |
|---|---|---|---|
| 1 | ★ **`func#30` = AES-128-CBC with an all-zero key *and* all-zero IV**, called by **7 of the 22 JNI natives** including the response handler `func#67` | **Critical** | This is a *keyless* cipher. Its output is a public function of the plaintext — anyone can encrypt/decrypt without ever extracting a secret. The key argument is accepted and then discarded (`memset` twice). |
| 2 | ★ **`func#85` = AES-**ECB**, called by 9 functions incl. 5 JNI natives** | **Critical** | ECB leaks block equality. Proven: `"A"*32` → the same 16-byte ciphertext twice; the PKCS#7 pad block always encrypts to `377222e061a924c591cd9c27ea163ed4` regardless of context. Any repeated JSON field is visible on the wire. |
| 3 | ★ **AES-192 key + two GCM nonces hardcoded in `.rodata`** (`0x17428` / `0x17448` / `0x17458`), behind only a 1-byte XOR + Base64 | **Critical** | Static across all installs and all three ABIs. 48 bytes of extraction ⇒ full decrypt. **Fixed nonce with a fixed key** breaks GCM catastrophically (nonce reuse ⇒ key-stream and auth-key recovery). |
| 4 | ★ **Plaintext AES key `0123456789abcdef` at `0x161ca` and `0x17ae0`** | **Critical** | Not even encoded. Feeds `func#226`/`func#73` (signature check) and `func#71`/`func#72` (OkHttp/Retrofit builders). |
| 5 | Four more 12-byte keys returned by constant getters (`func#86`, `#159`, `#160`, `#161`) | **Critical** | All argument-independent; one call each under emulation recovers them (§11.5). |
| 6 | The signature pin is a **double-Base64 of a hex string** stored in **plaintext** (no XOR layer), not a DER/SPKI blob | High | Trivially decoded offline; no need to run the app. And it is the SHA-256 of the *APK signer certificate*, so it can be **forged on the Java side** by returning the original cert bytes from `PackageManager.getPackageInfo` — the native compare then passes without any patch (§6.5, §10 item 31). |
| 7 | Ciphertext is transported as **lowercase hex**, not Base64 | High | 2× wire size, and length leaks the exact padded plaintext size. Also makes it trivially greppable in logs. |
| 8 | String protection is **single-byte XOR 0x5A** split across two MBA immediates (`0x3A`, `0x60`) | High | One `bic/and/orr/eor` pattern to search for; a 10-line script decodes everything (§5). |
| 9 | Root check is **`access()` on 9 fixed paths only** | High | Magisk Hide / a renamed `su` / Zygisk DenyList defeats it completely. No `su -c`, no package check, no mount-namespace probe. |
| 10 | Frida detection is **name-based** (`gum-js-loop`, `libfrida-gadget`, `re.frida.server`) | High | Renamed frida-server + `-l` gadget or a `stalker`-only script is invisible. No port 27042 probe, no `ptrace` self-attach, no inline-hook scan. |
| 11 | Hook detection is **`strstr` over `/proc/self/maps`** | High | Does not inspect PLT/GOT for actual inline hooks; a memory-only injector that unlinks its mapping is invisible. |
| 12 | **No** emulator detection, **no** `TracerPid`, **no** debugger self-attach, **no** Play Integrity | Medium | Large gap for a "hardened" library — an emulator + attached `lldb` is entirely undetected. |
| 13 | Signature check uses deprecated `PackageInfo.signatures` (not `GET_SIGNING_CERTIFICATES`) | Medium | Vulnerable to the classic Janus/fake-ID style signature-scheme-1 confusion on API < 28 paths. |
| 14 | CFF inflates 12 functions to 50.8 % of the binary | Low (cost) | Makes automated decompilation noisy but is **fully reversible** — the state variable lives in a callee-saved register and each block ends with `mov wN,#imm; b dispatcher`. |
| 15 | Pin comparison is not constant-time | Low | Theoretical; not exploitable remotely here. |

**You do not need to bypass anything to read the traffic.** Because of rows 1–2 above the
protocol is fully breakable offline:

```python
# decrypt anything produced by func#30 (7 JNI natives, incl. the response handler)
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
ct = bytes.fromhex(hexstring)                       # lowercase hex off the wire
pt = unpad(AES.new(b"\x00"*16, AES.MODE_CBC, b"\x00"*16).decrypt(ct), 16)

# decrypt anything produced by func#85 (9 callers, 5 JNI natives)
pt = unpad(AES.new(key.encode(), AES.MODE_ECB).decrypt(bytes.fromhex(hexstring)), 16)
# key ∈ {"0123456789abcdef", "5VEJK9Uk4d0elpVT", <12-byte b64 family of §4.2.4>, "null"}
```

**Neutralisation order if you must run it dynamically:**
1. Hook `func#193` (`0x14193c`) — 3 args `x0=src, x1=len, x8=dst`. Dumping `dst` after return
   recovers **every** key/IV/nonce install at runtime, including any missed statically. This
   single hook defeats the whole string-protection scheme.
2. Hook `func#85` (`0x10c470`) and `func#94` (`0x110b70`) at entry/exit: `(x0=pt, x1=key) → sret`.
   That gives you plaintext **and** the live key for every request and response, with no
   cryptanalysis at all.
3. Force-return `false` from `func#200` (`0x145f88`), `func#99` (`0x115770`), `func#162` (`0x136cb8`), `func#225` (`0x157f38`), `func#169` (`0x13ba30`).
4. For TLS interception hook `func#253`/`func#254` to skip `CertificatePinner$Builder.add` — patching `.rodata:0x15084` does **not** help there, because that blob is the **APK-signature** pin, not a TLS SPKI (§10 item 30). For the signature check itself, hand the original certificate back from `PackageManager.getPackageInfo` (§6.5).
5. Neutralise `func#98` (`0x114fbc`) `clock()` delta.
6. Only then attach Frida — remember `func#226` calls `func#99` **immediately before** applying pins.
7. **Beware the 148 reachable `b .` traps (§3.8).** If a hook or patch perturbs an opaque
   predicate, control flow lands on a self-loop and the thread hangs silently instead of
   erroring. Never "fix" a self-loop you find; work out which predicate guards it and satisfy
   the predicate instead. `func#224 @ 0x157628` traps at `0x1576ac`, the string decryptor
   `func#193` at `0x141ca0`, `0x141d4c` and `0x1420e4`.

---

## 9. Artifacts produced

All under `work/analysis/` (regenerable from the APK):

| File | Content |
|---|---|
| `annotated_arm64.txt` | **399,954 lines** (397,774 annotated instructions + function headers) — full Capstone disassembly of all 1,090 functions, every `adrp/add` annotated with its resolved target, every `bl` with its PLT name |
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
| `dex_protocol.txt` | **DEX protocol dump** — 65 Instagram endpoints, 61 `X-IG-*` headers, backend URLs, and the model fields of `SecretKey` / `InstagramReqInfo` / `BaseResponse` / `AppInfo` / `BaseInfo` / `DeviceModel` / `InstagramAccount` / `Order` |
| `xor_referenced.txt` | the **241** XOR-`0x5A` strings that actually have an `adrp/add` xref (i.e. are live), each with its owning function |
| `proto_native.txt` | the 19 decoded native-side protocol strings categorised ENDPOINT / DETECTION / OTHER, plus per-function string-ref maps |
| `nested_b64.txt` | the 10 multi-layer Base64 strings (L2–L4) fully unwound |
| `selfloops.json` | **all 712 `b .` addresses**, per-function counts, and how many are reachable (§3.8) |

#### Dynamic-analysis artifacts (revision 2)

| File | Content |
|---|---|
| **`emu.py`** | the Unicorn AArch64 harness — segment loader, 2,814 relocations, PLT/libc/libc++ shims, libc++ `std::string` both SSO and long form, TLS canary, unmapped-page handler, code tracing, `call(fn, x0..x8)` driver (§11.0) |
| **`aesref.py`** | independent table-free FIPS-197 AES written for this report: `expand`, `enc_block`, `pkcs7`, `ecb`, `cbc_enc`; self-checks against the standard AES-128/256 vectors |
| **`verify_all.py` → `verify_all.txt`** | **the evidence file.** Re-runs every ★ PROVEN claim in §4/§7 and writes the unedited output — 27 ECB KATs, the 221-length CBC sweep, the 5-key-argument matrix, the decoder blobs, the getters, the `func#14` struct probe, the 9-table comparison |
| `probe14.py` … `probe14f.py` | the `func#14` argument/struct-layout probes that produced §11.7 |
| `probe30long.py`, `probe30big.py`, `probe30c.py`, `probe30d.py`, `probe30bnd.py`, `probe30bnd2.py`, `probe30ovf.py`, `probe30ovf2.py`, `probe30w.py` | the `func#30` length-boundary investigation (block-by-block CBC comparison, ECB cross-check up to 20 000 bytes, `UC_HOOK_MEM_WRITE` frame map) → §10 item 27 |
| `probe85big.py` | `func#85` exactness over lengths 200–20 000 |
| **`aesdec.py`** | **revision 4**: reference AES *decryptor* (ECB/CBC + PKCS#7 unpad). Regenerates `Te0`/`Td0` from first principles and compares byte-for-byte with the `.so`'s tables at `0x118b0`/`0x129b0` plus `Te1..3`/`Td1..3` as right-rotations, and `RSbox @0x139b0` — so the reference and the binary are provably doing the same arithmetic (§11.11) |
| **`keyrec36.py`, `keyrec36b.py`, `f36_derive.py`, `f36_stackkey.py`** | **revision 4**: the `func#36` investigation — `rijndael_setup` argument capture (resolving `x1` as raw buffer *or* libc++ long `std::string`), input-length × second-argument sweep, determinism test, stack pre-fill control (§11.11(a), §10 item 34) |
| **`gcm_material.py`** | **revision 4**: runs `func#157`/`func#158` and searches the emulated heap for every stage of the `0x17428`/`0x17448`/`0x17458` encoding chain (§11.11(c), §10 item 36) |
| **`f30_blob.py`** | **revision 4**: `func#30` re-verification with a `func#14` hook, plus the heap search that shows the `0x1606a` blob is dead (§11.11(d), §10 item 37) |
| **`b64_sweep.py`, `b64_all.py`, `blob_hunt.py`** | **revision 4**: enumerate every Base64-hidden C string in `.rodata` (1–3 layers, plus XOR-then-Base64), map each address to the functions whose `data_refs` contain it, and filter for URLs / hostnames / detection tokens |
| **`callees.py`** | **revision 4**: dump a function's direct callees and data refs with labels for the known crypto/detection anchors |
| `deob.py` → `deob/F<N>.txt` | **full-CFG deobfuscator**: BFS block traversal, labelled output, every `bl` annotated with its `func#` and every `adrp/add` with its resolved data target |
| `cff3.py` → `deob/f<N>.txt` | CFF single-path lineariser (state-register resolver) |
| `deob/` generated for | 26, 28, 30, 36, 41, 42, 54, 55, 56, 57, 60, 61, 67, 76, 84, 85, 86, 90, 94, 157, 158, 160, 161, 162, 176, 177, 178, 191, 193, 224 |
| `xorcorp2.py` → `xor_referenced.txt` | the referenced-XOR corpus generator |
| `keymat.py`, `keys2.py`, `nested.py`, `proto2.py` | key-material Base64 scanners and the protocol extractor |
| static scripts | `elf_model.py`, `disasm.py`, `xref.py`, `funcmap.py`, `decode_refs.py`, `decrypt_strings.py`, `obf_metrics.py`, `ident.py`, `ident2.py`, `kdf.py`, `mode.py`, `custom.py`, `final_crypto.py`, `reqresp.py`, `t85.py`, `t157.py`, `t193.py`, `f30.py`, `f36.py`, `f36b.py`, `f36c.py`, `f157.py`, `trace157.py`, `dex_scan.py`, `dex_jni.py`, `dex_layer.py`, `dex_models.py`, `dex_proto.py`, `dex_api.py`, `dex_crypto_xref.py` |

### Reproduction

```bash
python3 -m venv .venv
.venv/bin/pip install capstone==5.0.7 lief==1.0.0 androguard==4.1.4 unicorn==2.1.4
unzip TopFollow_v845-Beta.apk -d work/apk_extracted
cd work

# ---- static ----
../.venv/bin/python analysis/elf_model.py  apk_extracted/lib/arm64-v8a/libtopfollow.so analysis/model_arm64.json
../.venv/bin/python analysis/funcmap.py            # -> funcmap.json
../.venv/bin/python analysis/decrypt_strings.py    # -> xor_strings.txt
../.venv/bin/python analysis/xorcorp2.py           # -> xor_referenced.txt
../.venv/bin/python analysis/deob.py 193           # -> deob/F193.txt  (any func#)
../.venv/bin/python analysis/dex_proto.py          # -> dex_protocol.txt

# ---- dynamic: re-proves every ★ PROVEN claim in this report ----
../.venv/bin/python analysis/verify_all.py         # -> verify_all.txt (~20 s)
```

To check a single cipher by hand:

```python
import sys; sys.path.insert(0,'analysis')
from emu import Emu
import aesref
e = Emu(); out = e.malloc(24); e.wr(out, b'\x00'*24)
e.call(0x10c470, x0=e.mkstring(b'hello'), x1=e.mkstring(b'0123456789abcdef'), x8=out)
print(e.getstring(out))                              # 674c7ef38e78cabd9cec9c125823a639
print(aesref.ecb(b'hello', b'0123456789abcdef').hex())   # identical
```

#### Instrumentation artifacts (revision 3) — `frida/`

Everything needed to move from "proven under emulation" to "captured live on a phone",
including on a **non-rooted** one. Full walkthrough: `frida/README_frida_gadget.md`.

| File | Content |
|---|---|
| **`frida/topfollow_agent.js`** | the Frida agent (1,989 lines). Module-wait via `dlopen`/`android_dlopen_ext` hooks + polling; sanity anchors (JNI_OnLoad export, S-box `@0x128b0`, Rcon `@0x13b10`, plaintext key `@0x161ca`); runtime self-calibration against the 22-entry `JNINativeMethod` table `@0x1b6198`; **entry-only** `Interceptor.attach` on `func#85/#94/#30/#36/#14/#193`, the 5 key getters and `func#157/#158`; read-only detection layer — **`/proc/*/maps` fd tracking on `__open_2`/`open` plus a length-preserving rewrite of every `read`/`__read_chk` buffer** (the library imports no `fopen`/`fgets`/`strstr`, item 39), `access()` su-path `ENOENT`, and a 30-token suppression list derived from the Base64-hidden strings — none of which ever touches a flattened body; Java hooks for the 22 natives, `CertificatePinner` neutralisation, trust-all TLS, and the §6.5C **signature forgery**; a from-scratch JS AES-128/192/256 (ECB+CBC, PKCS#7) and SHA-256 for offline decryption and self-verification; 17 `rpc.exports` |
| **`frida/test_agent_offline.js`** | `node frida/test_agent_offline.js` — loads the agent into a Node VM with the Frida API stubbed and asserts **138 known-answer checks**: FIPS-197 AES vectors, all 11 `func#85` vectors of §11.2, `func#94` round-trips, all 5 `func#30` vectors of §11.3, `rpc.exports.decrypt`, the 3-layer `.rodata` secret decoding against the *real* `libtopfollow.so` bytes, the 9 AES table anchors, all 22 `JNINativeMethod` slots re-derived from `analysis/relocs.json`, **every Base64-hidden detection token decoded live out of the binary and asserted covered by `MAPS_NOISE`**, the Base64 endpoint/pin decodes, and `filterMapsBuffer`'s length-preserving rewrite (§11.12) |
| **`frida/selftest_real_so.js`** | `node frida/selftest_real_so.js` — runs `rpc.exports.selfTest()` and `rpc.exports.signature()` with the agent's `MOD` resolved against the **real `libtopfollow.so` bytes on disk**: `NativePointer.read*` is backed by the file buffer and `Process.findModuleByName` is stubbed, so the agent resolves `MOD` through its own `findModule()` and the six *live* `.rodata` vectors run exactly as on a device. Exits non-zero unless **26/26 pass with 0 skipped** and `liveMatchesPin == true` |
| **`frida/clone_signer.py`** | proves and exploits §6.5B: reads the signer certificate out of the APK's v2 Signing Block, reads the pin blob out of `libtopfollow.so @0x15084`, double-Base64-decodes it and asserts `SHA-256(cert DER) == pin`; then rebuilds a structurally identical certificate with a fresh RSA-2048 key and emits `frida/keys/topfollow_clone.p12` + PEMs for `apksigner` |
| **`frida/repack_apk.py`** | pure-Python APK surgery — **no Java, no apktool, no zipalign, no apksigner**. Copies all 1,266 entries raw (verified: *zero* payload or compression-method changes), injects `lib/arm64-v8a/libgadget.so` + `libgadget.config.so` STORED and **4096-byte aligned** via the `0xd935` extra field (the same trick `zipalign -p 4` uses), drops stale `META-INF` signature files and the APK Signing Block, and re-verifies alignment and CRCs on the result |
| `frida/run_frida.py` | the runner: USB/remote/local device, attach-by-name (`Gadget`) or spawn-by-package, injects `TF_CONFIG`, streams the agent's tagged messages, and gives a REPL over all `rpc.exports`. `--offline-decrypt <hex>` decrypts captured ciphertext **with no phone at all** by driving the agent's JS under Node (with a self-contained pure-Python AES fallback whose S-box is *computed*, not transcribed) |
| `frida/libgadget.config.so` | Gadget config, `listen 127.0.0.1:27042`, **`on_load: wait`** — the app blocks at `System.loadLibrary("gadget")` until you attach, so nothing in `JNI_OnLoad` runs before the hooks are armed |
| `frida/libgadget.config.resume.so` | same but `on_load: resume` — app runs immediately, attach later |
| `frida/libgadget.config.script.so` | `type: script`, `path: ./libgadget.script.so` — the agent is baked into the APK and runs with no PC attached |
| `frida/gadget/` | drop `libgadget.so` here (`.gitignore`d; download URL in the README) |
| `frida/keys/` | generated keystores / the original certificate DER (`.gitignore`d) |

```bash
# no phone required — re-proves the agent's crypto against the real .so bytes
node frida/test_agent_offline.js                        # -> PASS 138 FAIL 0
node frida/selftest_real_so.js                          # -> passed=26/26 skipped=0, liveMatchesPin=true
python3 frida/clone_signer.py                           # -> asserts SHA-256(cert) == pin
python3 frida/repack_apk.py --dry-run                   # -> manifest + DEX-patch status
python3 frida/run_frida.py --offline-decrypt \
        f49288051d7d9decc641ea07eb7ff32cbde7e2be9f3006617f3938a20f63549c\
fc144d3ce97d67ecc55475f0dfeec781                          # -> {"order_id":12345,...}
```

---

## 10. Corrections to earlier working notes

Recorded so the mistakes are not repeated:

1. ~~**Blob `0x1742b` does not decode under any single-byte XOR — status: encrypted, key not recovered.**~~
   **SUPERSEDED in revision 2.** `0x1742b` is byte 3 of the 32-byte blob that starts at
   **`0x17428`**; the sweep had been run on the wrong start offset, which is why every key
   failed. Starting at `0x17428` it decodes under **XOR `0x5A`** to
   `At91IxVnRSbFppV0UxNFdUSnplTW5ONA`, and `func#193` was then *executed* on it to confirm
   (§11.1). It is **not** Instagram API paths — it is the app's **24-byte AES-192 key**, Base64-encoded.
   The real Instagram endpoints are separately Base64-encoded at `0x159ec` / `0x15c02` / `0x15de3` (§5.2).
2. **Anti-hook scanning is `func#200 @ 0x145f88`, not `func#60`.** `func#60` is JNI slot 9 (`q.r(JsonObject,String,String)`, 44,957 insns) and merely *Base64-decodes* some of the same tokens. The XOR-0x5A blob owner is `func#200` (9 data refs inside the blob).
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

### Revision 2 — corrections produced by emulation (§11)

Every item below was believed in revision 1 and is **wrong**. Each is now backed by an executed
test in `work/analysis/verify_all.txt`.

15. **`.rodata` key blobs are NOT stored raw.** Revision 1 read `0x17428` / `0x17448` / `0x17458`
    as "the AES-256 key and IV, consumed verbatim". They are **XOR-`0x5A` ciphertexts of Base64
    text**. The decode is three layers, not zero: `XOR 0x5A → Base64 text → raw key bytes`.
16. **The main key is AES-192 (24 bytes), not AES-256 (32 bytes).** `0x17428` holds 32 *encoded*
    bytes → 32 Base64 chars → **24** key bytes (`02df752315674526c5a695745313457544a7a654d6e4e340`).
    The 32-byte figure was the encoded length.
17. **`0x17448` and `0x17458` are 12-byte values, not 16-byte IVs** → `58c544c151b4d9e185955991`
    and `334544c151add1a549b908c5`. 12 bytes is a **GCM nonce**, not a CBC IV. This is what
    points at `AES/GCM/NoPadding` (a string that exists only in the DEX).
18. **`func#193 @ 0x14193c` is the XOR-`0x5A` string decoder, not a `memcpy`.** Signature
    `x0 = src`, `x1 = len`, `x8 = dst (std::string sret)`, returns `char*`. Executed and
    byte-verified against an offline `b ^ 0x5A` (§11.1).
19. **`func#85` / `func#94` are AES-ECB + hex, not "envelope build/parse".** 27/27 known-answer
    tests match FIPS-197 exactly for 16-, 24- and 32-byte keys; `func#94` is the exact inverse
    (§11.2). The "envelope" reading came from the hex encoder and the `"null"` sentinel.
20. **`func#30` ignores its key argument.** Revision 1 assumed it used a per-call key. It
    `memset`s a 16-byte buffer to zero twice and runs **AES-128-CBC with key = 0 and IV = 0**.
    Proven by feeding it five different key arguments and getting byte-identical output (§11.3).
21. **SHA-1 IS present.** Revision 1 listed SHA-1 under "not present". `func#201` is the SHA-1
    round function, `func#199` the update, `func#202` the wrapper (§4.3A).
22. **The AES table addresses in revision 1 were wrong.** `Rcon` is at **`0x13b10`**, not
    `0x135b0`; `0x135b0` is **`Td3`** (a byte-rotation of `Td0`). There is **no** `setup_log`
    and **no** `setup_alog` anywhere in the file — the earlier "LibTomCrypt log/alog" claim came
    from misreading `Te1/Te2/Te3` rotations as GF tables. All nine tables were regenerated from
    FIPS-197 and compared word-for-word (§11.8).
23. **`func#86`'s returned key `5VEJK9Uk4d0elpVT` does not exist anywhere in the file**, in
    plaintext, under any single-byte XOR, or Base64-encoded. `func#86` references `0x17307`,
    which decodes to neither. The value is synthesised at runtime. Do not claim a `.rodata`
    address for it.
24. **`func#36` is not `func#30`'s inverse**, and its key argument is ignored (four different
    keys → identical output; six in the revision-4 re-run). Feeding it `func#30`'s ciphertext
    yields 8 bytes of unrelated data (§11.4). Its only caller is `func#252`, on the
    certificate-pinner path. Superseded in part by item 34: the cipher *is* AES-256-ECB and the
    key is not a fixed constant (§11.11(a)).
25. **`func#14`'s third argument is not a table pointer.** It is `0x16c10`, which is plain
    ASCII `.rodata` (`" expression\0x21\0\0eHBvc2Vk\0BRAND"`). It is never dereferenced as a
    table (§11.7).
26. **`func#16 @ 0x35518` is the decrypt-side setup and calls *both* `func#12` and `func#13`**,
    while the encrypt-side `func#14` calls neither. Revision 1 described `#15`/`#16` as
    symmetric wrappers.
27. **NEW FINDING (revision 2): `func#30` diverges above 220 bytes of plaintext.** Its output
    length stays correct but the bytes from ciphertext offset **208** onward differ from
    AES-CBC. `func#85` is exact for every length up to 20 000 bytes, so this is specific to
    `func#30`'s CBC scratch. A `UC_HOOK_MEM_WRITE` trace shows writes at frame offsets
    **beyond** `func#30`'s own `sub sp, sp, #0x570` frame. Treat `func#30` as a
    **fixed-208-byte-buffer CBC** and, on-device, check whether a >220-byte plaintext is a
    *stack buffer overflow* rather than an emulation artifact. Every request/response payload
    this report decoded was well under that limit.
28. **NEW FINDING (revision 2): 712 `b .` infinite-loop instructions across 79 functions, 148 of
    them reachable.** Revision 1 mentioned one trap in `func#169`. The real count and
    distribution are in §3.8 (`work/analysis/selfloops.json`).
29. **NEW (revision 3): revision 2's §2.2 "slug → `func#`" table was shifted by one row and has
    been rebuilt.** It paired slot 0 (`x0011a4c2`, `fnPtr = 0x3eab4`) with `func#56 @ 0x435b8`;
    `0x3eab4` is `func#51`. The 22 JNI natives are in fact **`func#51` … `func#72` in slot
    order** — 22 consecutive IDs — and `func#73 @ 0x103ad8` is the first non-JNI function after
    them. Every `fnPtr` *address* quoted in revision 2 was correct, and every address-keyed
    finding (§4, §5, §6, §11) still holds; only the `func#` labels attached to the Java slugs,
    and the "JNI m*n*" numbering derived from them, were wrong. All such labels have been
    replaced by slot numbers plus the `q.a`…`q.v` delegate name, which is now derived
    mechanically from the DEX. Concretely: `func#73` is called by slots 0 and 6 (**not** a JNI
    native itself — it sits past slot 21); the 180 KB / 44,957-insn monster is `func#60` =
    slot 9 `q.r`; the 160 KB hub is `func#57` = slot 6 `q.v`; `func#64` = slot 13 `q.b`;
    `func#67` = slot 16 `q.p`; `func#70` = slot 19 `q.q`; `func#166` (`order_stamp2`) is not a
    JNI native at all. See §2.2 and the new §2.2A call-graph table.
30. **NEW (revision 3): the `0x15084` blob is a *signature* pin, not a TLS pin, and it is
    double-Base64, not triple.** Stored as 120 characters of **plaintext** Base64 (no XOR-`0x5A`
    layer, unlike nearly every other secret here). Decoding twice yields
    `d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e`, which is exactly
    **`SHA-256` of this APK's own signer-certificate DER (864 bytes)** — extracted from the v2
    Signing Block and matched byte-for-byte (§6.5B, `frida/clone_signer.py`). Revision 2's
    claim that `func#253` "adds `sha256/d845591e…` for the Instagram hosts" is **withdrawn**:
    `0x15084` has exactly one referrer in the whole library, `func#245`, and neither `func#253`,
    `func#254`, `func#71` nor `func#72` references it. No `sha256` substring and no 43-char
    Base64 pin exist anywhere in the `.so` (plain or XOR-`0x5A`). Pinning is real
    (`CertificatePinner$Builder.add` is called) but **the pin values are not static constants** —
    they arrive as arguments. §6.6 rewritten accordingly.
31. **NEW (revision 3): the signature check is defeatable from Java without writing a single
    byte of the library.** `func#73`/`func#226` never read the APK; they call
    `PackageManager.getPackageInfo(pkg, GET_SIGNATURES)` and hash `Signature.toByteArray()`.
    Returning the *original* 864 certificate bytes from that call makes the native SHA-256 land
    on the pinned digest by itself (§6.5C, implemented in `frida/topfollow_agent.js` §7.4,
    including `SigningInfo` for API 28+ and a `Signature.toByteArray` fallback net). This is
    strictly safer than force-returning `func#226`, which is control-flow flattened with 68
    reachable `b .` traps and whose result polarity is unproven.
32. **NEW (revision 3): five addresses in revision 2's §6.5/§6.6 string tables were wrong.**
    Verified by re-reading the bytes: `getPackageInfo` is at **`0x15349`** (not `0x15b8b` — that
    is `com/nivaroid/topfollow/application/G`, the app's context singleton, with
    `()Lcom/nivaroid/topfollow/application/G;` at `0x15bb0`); `CertificatePinner$Builder`'s
    `add` is at **`0x1649a`** (not `0x1649e`, which is `certificatePinner`); `nonce` is at
    **`0x151f5` / `0x15a43`** (not `0x14ee5`, which is
    `(JLjava/util/concurrent/TimeUnit;)Lokhttp3/OkHttpClient$Builder;` — the read/write-timeout
    signature); `BRAND` is at **`0x16c1a`** (`0x16c10` is an *empty* string, consistent with
    item 25). Also new: the Context for the signature check is obtained via
    `G.getInstance().getContext()`, not passed in from Java — `MyApp.onCreate()` does
    `G.getInstance().a = this`.
33. **NEW (revision 3): `func#57` (JNI slot 6, `q.v(JsonObject)`) is the hub of the library and
    the root check hangs off it.** 160,912 B / 40,228 insns, and the only JNI native that
    reaches `func#73`, **both** GCM context builders (`func#157` *and* `func#158`), both ciphers
    (`func#85`, `func#30`), all three scanners (`func#99`, `func#162`, `func#200`), `func#97`
    (ANDROID_ID) and `func#152`/`#153`/`#154`/`#156`. `func#169` (root) is reachable from Java
    *only* through it, via `func#154`. If you can hook one JNI native, hook this one (§2.2A,
    §7.13).

34. **NEW (revision 4): `func#36`'s key is not a fixed internal constant — the key buffer is a
    slice of its own stack frame, and the cipher is AES-256-ECB.** Hooking `func#14`
    (`rijndael_setup`) inside a `func#36` call gives `x3 = keylen = 32` every time, so the
    algorithm is AES-256, and `x1 = 0x81efaf1` — an address *inside* `func#36`'s frame that
    overlaps a local `std::string`, not a `.rodata` constant. Revision 1–3's "fixed internal
    key" (§4.4 row, §7.9, §11.4) was an artefact of assuming the key had to be static. Also
    new: `func#36`'s only caller is `func#252`, whose only caller is **JNI slot 20 `q.k`
    (`func#71`)** — so `func#36` *is* reachable from Java, via `q.k → #252 → #36`, on the
    OkHttp/`CertificatePinner` construction path (§11.11).
35. **NEW (revision 4): the GCM path is native, not a `javax.crypto.Cipher` wrapper — and this
    is now proven by absence, not inferred.** `javax/crypto`, `AES/GCM`, `NoPadding`, `Cipher`,
    `SecretKey`, `GCMParameterSpec`, `IvParameterSpec` and `doFinal` appear **nowhere** in the
    1,805,400-byte `.so`, neither as plain C strings nor Base64-encoded. The GCM core `func#191`
    is reached by exactly two paths (`#157 → #177 → #191` and `#241 → #191`, the latter from
    `func#67`), so the JNI natives that can reach it are **slot 6 `q.v` (`#57`), slot 13 `q.b`
    (`#64`) and slot 16 `q.p` (`#67`)** — response handling included.
    **Correction (revision 5):** the sentence that used to follow here — *"`func#172` is the GF
    arithmetic core: it loads the S-box and inverse S-box through the GOT slots `0x1bb638 →
    0x128b0` and `0x1bb640 → 0x139b0`"* — **was wrong and is withdrawn.** Those two GOT slots
    really are `R_AARCH64_RELATIVE`, but their addends are `0x1c28a0` and `0x1c2d2c`, which are
    in **`.bss`**, not `.rodata`; they are control-flow-flattening state globals. `func#172`'s
    entire body is one MBA opaque predicate that reads them (`(v+~k+k)*v == v²` and `w < 10`,
    which is always true) — 149 instructions, no calls, no table. Re-scanning every function
    *individually* (resetting the `adrp` page register at each entry, which the earlier
    whole-`.text` scan did not do) shows that **exactly five functions in the library touch the
    Rijndael tables**, and `func#172` is not one of them (§11.13).
36. **NEW (revision 4): the GCM key/nonce blobs are XOR-`0x5A` + *one* Base64 layer, not two.**
    `0x17428` (32 B) → XOR `0x5A` → `At91IxVnRSbFppV0UxNFdUSnplTW5ONA` (32 ASCII chars) →
    single `b64decode` → `02df7523…44a7a654d6e4e340` (24 B AES-192 key). `0x17448` (16 B) →
    `WMVEwVG02eGFlVmR` → `58c544c151b4d9e185955991` (12 B). `0x17458` (16 B) →
    `M0VEwVGt0aVJuQjF` → `334544c151add1a549b908c5` (12 B). All three land in **one contiguous
    64-byte XOR-`0x5A` blob at `0x17428…0x17468`**, decoded in a single `func#193` pass. This is
    a *different* encoding from the signature-pin blob at `0x15084`, which really is plaintext
    double-Base64 with no XOR layer (item 30) — the library uses both conventions (§11.11).
37. **NEW (revision 4): `func#30`'s `0x1606a` reference is dead.** `func#30` is confirmed as
    `lowercase_hex( AES-128-CBC( PKCS#7(pt), key = 0^16, IV = 0^16 ) )` — `pt = b''` yields
    `0143db63ee66b0cdff9f69917680151e`, which is `ECB_enc(0^16, 0^16)` because CBC with a zero
    IV degenerates to ECB on the first block. The 16-char Base64 string `U0dKR01FNW9OV3h3`
    at `0x1606a` — which is **two** layers deep, `U0dKR01FNW9OV3h3 → SGJGME5oNWxw → HbF0Nh5lp`
    (11 printable ASCII chars; the revision-4 note calling it "12 bytes `53474a474d45356f4e577877`,
    GCM-nonce shaped" treated the *Base64 text* as if it were the decoded bytes, and is withdrawn)
    — that `func#30` references **never appears on the heap during execution** — it sits on an opaque-predicate
    path, exactly like `func#86`'s `0x17307` (item 22). Do not treat it as `func#30`'s nonce.
38. **NEW (revision 4): code duplication is *not* one of this library's obfuscation techniques.**
    Hashing all 1,090 recovered function bodies (≥ 64 B) yields exactly **one** pair of
    byte-identical functions (`func#825` / `func#831`, 100 B each). Every CFF state machine,
    every MBA predicate and every scanner is a unique byte sequence. `func#241` and `func#191`
    call the identical five-function set `{#79, #172, #173, #674, #682}` but differ in 4,193 of
    their bytes — same role, independently obfuscated. Practically: pattern/signature-based
    deobfuscation cannot be amortised across functions here; each one has to be handled
    separately (§11.11).

39. **NEW (revision 4): `libtopfollow.so` imports no `fopen`, no `fgets`, no `strstr`, no `stat`
    and no `lstat` — so the maps-hiding strategy described in revisions 1–3 could not have
    worked.** The complete import table is **88 symbols**; the file-IO ones are `__open_2` (8 call
    sites), `__read_chk` (6), `read` (3), `close` (6) and `access` (1). Exactly three functions
    use the read path, and they are the *maps readers*:

    | reader | address | size | called by |
    |---|---|---|---|
    | `func#129` | `0x11deb0` | 4,900 | `func#99` (anti-Frida), `func#225` (maps integrity) |
    | `func#198` | `0x143694` | 5,872 | `func#162` (anti-Frida, Base64 tokens), `func#200` (anti-hook) |
    | `func#213` | `0x151e68` | 6,080 | `func#60` (the 179,828-byte Xposed/Riru/Substrate scanner) |

    Each scanner therefore reads `/proc/self/maps` with `open()` + `read()` and searches the
    buffer with its **own inlined byte loop** (`memcmp` ×5 and `memchr` ×4 exist in the import
    table but are used by libc++ and by `func#75`/`func#149`, not by the scanners). The §7.5 and
    §7.6 reconstructions have been rewritten to the `open`/`read`/`close` shape, §6's mechanism
    paragraph corrected, and `frida/topfollow_agent.js` now filters the **`read()` buffer**
    instead of `fgets` output (§11.12). The `dl_iterate_phdr` import belongs to `func#1074`, the
    unwinder — it is *not* a detection vector, and `syscall` ×2 belongs to `func#746`, a libc++
    helper.
40. **NEW (revision 4): the detection tokens are stored as plain Base64 C strings, and the
    complete set is now enumerated.** `work/analysis/b64_all.py` decodes every Base64-shaped C
    string in `.rodata` (1–3 layers) and maps each address to the functions whose `data_refs`
    contain it — 39 strings, of which the detection-relevant ones are:

    | token | address | layers | owning function |
    |---|---|---|---|
    | `frida` | `0x15be1` | 1 | `func#162` |
    | `re.frida.server` | `0x1607f` | 1 | `func#162` |
    | `gum-js-loop` | `0x161eb` | 1 | `func#162` |
    | `libfrida-gadget` | `0x16d97` | 1 | `func#162` |
    | `/proc/self/maps` | `0x15db5` | 1 | `func#60`, `func#162`, `func#225` |
    | `libbridge.so` | `0x15541` | 1 | `func#60` |
    | `riru` | `0x156df` | 1 | `func#60` |
    | `libcso_substrate` | `0x156e8` | 1 | `func#60` |
    | `substrate` | `0x15dd4` | 1 | `func#60` |
    | `edxposed` | `0x16204` | 1 | `func#60` |
    | `lsposed` | `0x167a9` | 1 | `func#60` |
    | `xposed` | `0x16c11` | 1 | `func#60` |
    | `ygsik` | `0x16f60` | 1 | `func#60` |
    | `rwxp` | `0x16336` | 1 | `func#225` |
    | `libart.so (deleted)` | `0x16b75` | 1 | `func#225` |
    | `libc.so (deleted)` | `0x16f69` | 1 | `func#225` |

    None of these literals appears in the binary, so a `strings`-based allowlist misses every one
    of them. The agent's suppression list is now generated from this table and
    `frida/test_agent_offline.js` **decodes the tokens straight out of the real `.so` and asserts
    coverage**, so the list cannot silently drift (§11.12).

---

## 11. Dynamic verification — running the library under emulation

Everything in §4 that is marked **★ PROVEN** was obtained by *executing* the real AArch64
machine code, not by reading it. This section is the evidence.

### 11.0 The harness

`work/analysis/emu.py` — a Unicorn `UC_ARCH_ARM64 / UC_MODE_LITTLE_ENDIAN` loader:

| Concern | How it is handled |
|---|---|
| Load | `libtopfollow.so` mapped at VA `0` exactly as the ELF LOAD segments describe (RX `0x0–0x1b2160`, RW `0x1b6160`, `0x1c02b8`); `.bss` tail zeroed |
| Relocations | all **2,814** entries from `analysis/relocs.json` applied — `R_AARCH64_ABS64` written directly, `R_GLOB_DAT`/`R_JUMP_SLOT` pointed at per-symbol stubs |
| libc / libc++ | 88 PLT entries + `malloc`/`operator new`/`free`/`memcpy`/`memset`/`memcmp`/`str*`/`clock`/`inflate*`/`pthread_*` shimmed in Python; file & network I/O stubbed to `-1` |
| `std::string` | libc++ ABI implemented both ways — SSO for ≤22 bytes (`len<<1` in byte 0, data at `+1`), long form `(cap, size, ptr)` with bit 0 of `cap` set |
| Stack canary | `tpidr_el0` points at a TLS block with a fixed value at `+0x28`, so `__stack_chk_guard` loads succeed |
| Unmapped access | `UC_HOOK_MEM_UNMAPPED` maps the page and logs it — this is how the *absence* of a read was proven for several functions |
| Tracing | optional `UC_HOOK_CODE` full-address trace, plus targeted hooks on `func#14` / `func#193` entry to capture arguments and struct addresses |

`work/analysis/aesref.py` is an independent, table-free FIPS-197 AES written for this report.
It self-checks against the standard vectors before it is allowed to judge anything:

```
AES-128  pt 00112233445566778899aabbccddeeff / key 000102..0f
         -> 69c4e0d86a7b0430d8cdb78070b4c55a   (FIPS-197 expected: same)  OK
AES-256  same pt / key 000102..1f
         -> 8ea2b7ca516745bfeafc49904b496089   (FIPS-197 expected: same)  OK
```

The driver is `work/analysis/verify_all.py`; its complete, unedited output is
`work/analysis/verify_all.txt` (229 lines). Everything quoted below is copied from that file.

### 11.1 `func#193` — the XOR-`0x5A` decoder, executed

```
### 11.1  func#193 @0x14193c — XOR-0x5A string decoder (3-arg: x0=src, x1=len, x8=dst)
  KEY_CT  @0x17428 len=32
      emulated  : 'At91IxVnRSbFppV0UxNFdUSnplTW5ONA'
      static^0x5A: 'At91IxVnRSbFppV0UxNFdUSnplTW5ONA'   agree=True
      base64 -> 24 bytes  02df752315674526c5a695745313457544a7a654d6e4e340
  IV_CT  @0x17448 len=16
      emulated  : 'WMVEwVG02eGFlVmR'
      static^0x5A: 'WMVEwVG02eGFlVmR'   agree=True
      base64 -> 12 bytes  58c544c151b4d9e185955991
  IV2_CT  @0x17458 len=16
      emulated  : 'M0VEwVGt0aVJuQjF'
      static^0x5A: 'M0VEwVGt0aVJuQjF'   agree=True
      base64 -> 12 bytes  334544c151add1a549b908c5
```

The emulated decoder and a one-line offline `bytes(b ^ 0x5A for b in blob)` agree on every
blob. **This single test closed the "key not recovered" gap left by revision 1** (§10 item 1).

### 11.2 `func#85` / `func#94` — AES-ECB, **27/27 known-answer tests**

27 combinations of {3 key sizes} × {9 plaintexts, 0 to 256 bytes} were encrypted by the real
`func#85` and compared with `aesref.ecb`. **All 27 matched byte-for-byte**, and `func#94`
recovered the plaintext in every non-empty case.

```
  TOTAL known-answer tests: 27/27 exact matches vs FIPS-197 AES-ECB/PKCS7/hex
```

Selected vectors (key `0123456789abcdef`, AES-128):

| plaintext | `func#85` output | `#94` round-trip |
|---|---|---|
| `hello` | `674c7ef38e78cabd9cec9c125823a639` | `hello` ✔ |
| `A`×15 | `8c22b46ae5492fada678b79e2bdbd0eb` | ✔ |
| `A`×16 | `3bfd04cc0d7ed55358e2cbe19de21383`<br>`377222e061a924c591cd9c27ea163ed4` | ✔ |
| `A`×31 | `3bfd04cc…21383` + `8c22b46a…bdbd0eb` | ✔ |
| `A`×32 | `3bfd04cc…21383` + `3bfd04cc…21383` + `377222e0…163ed4` | ✔ |
| *(empty)* | `null` | n/a |
| `{"user":"abc","pass":"xyz"}` | `473f9aa1dd7694a1f39c613225cce529`<br>`a588c9e9d7c7f8f9cb801491e4a2acd5` | ✔ |
| `The quick brown fox…` (43 B) | `08eaec72…fba1ae2433a9674ca3f58a8f2efdfba9` | ✔ |
| `bytes(range(256))` | 288 hex chars, matches | ✔ |

AES-192 (`bytes(range(24))`) and AES-256 (`bytes(range(32))`):

| key len | `#85("hello", key)` | match |
|---|---|---|
| 24 | `12056740635d5dd4124b24264bb8a00a` | ✔ |
| 32 | `91684487c34c3456eb4e901cef884a1e` | ✔ |

**ECB is proven, not inferred**, by three independent observations:

```
  ECB block-equality leak  #85('A'*32) = 3bfd04cc0d7ed55358e2cbe19de21383
                                       3bfd04cc0d7ed55358e2cbe19de21383
                                       377222e061a924c591cd9c27ea163ed4
      ct[0:32] == ct[32:64]  ->  True
      trailing pad block of a 46-byte pt = 37158a170356aae288a994d0dbf285b1
      identical to #85(pad-only)         = 37158a170356aae288a994d0dbf285b1
```

* two equal plaintext blocks ⇒ two equal ciphertext blocks (no chaining);
* a 15-byte and a 31-byte plaintext share their last ciphertext block, because both pad to a
  block whose content depends only on the tail;
* the pad block's ciphertext is independent of everything before it.

Key-length gate, exactly as claimed in §7.9:

```
  #85('hello', keylen= 5) -> b'null'
  #85('hello', keylen=17) -> b'null'
  #85('hello', keylen=20) -> b'null'
  #85('hello', keylen=31) -> b'null'
  #85('hello', keylen= 0) -> b'null'
```

`func#85` was additionally run on plaintexts of **every length from 200 to 260 and at 300, 512,
1 024, 4 096 and 20 000 bytes** — all exact. It has no input-length limit.

### 11.3 `func#30` — AES-128-CBC with a **zero key and zero IV**

Five different key arguments, five plaintexts. Every cell is byte-identical to
`AES-128-CBC(key=0×16, iv=0×16)`:

```
  pt[5] = b'hello'
     keyarg=b''                -> 9834ed518cbc8fbe9af3c6ecb75eb8c0   MATCH zero-key CBC
     keyarg=b'0123456789abcd'  -> 9834ed518cbc8fbe9af3c6ecb75eb8c0   MATCH zero-key CBC
     keyarg=b'\x00\x01…\x0c\r'      -> 9834ed518cbc8fbe9af3c6ecb75eb8c0   MATCH zero-key CBC
     keyarg=b'whatever-key!!'  -> 9834ed518cbc8fbe9af3c6ecb75eb8c0   MATCH zero-key CBC
     keyarg=b'\xff'×16              -> 9834ed518cbc8fbe9af3c6ecb75eb8c0   MATCH zero-key CBC
```

| plaintext | `func#30` output (= zero-key CBC) |
|---|---|
| *(empty)* | `0143db63ee66b0cdff9f69917680151e` |
| `hello` | `9834ed518cbc8fbe9af3c6ecb75eb8c0` |
| `A`×16 | `b49cbf19d357e6e1f6845c30fd5b63e3`<br>`0c747680a9e9970389a2bdd752b4b1c3` |
| `{"order_id":12345,"type":"follower"}` | `f49288051d7d9decc641ea07eb7ff32c`<br>`bde7e2be9f3006617f3938a20f63549c`<br>`fc144d3ce97d67ecc55475f0dfeec781` |

Note the empty-plaintext behaviour differs from `func#85`: `func#30("")` does **not** return
`"null"` — it encrypts the bare PKCS#7 pad block and returns
`0143db63ee66b0cdff9f69917680151e` = `AES-ECB(0x10×16, key 0)`. That constant is therefore a
**reliable oracle**: any `func#30` ciphertext beginning with those 32 hex chars carried an
empty payload.

An exhaustive length sweep was run with a **fresh emulator per length**:

```
  --- exhaustive length sweep (fresh emulator per length) ---
    first divergence at ptlen=221 (padded=224, 14 blocks); ciphertext byte 208
    exact matches: 221 lengths (0..220 contiguous, then divergent from 221 upward)
  NOTE func#85 (ECB) is exact for every length tested up to 20000 bytes -> the divergence
       is specific to func#30's CBC chaining scratch, not to the emulator's std::string ABI.
```

So: **`func#30` is exactly zero-key AES-128-CBC for every plaintext of 0–220 bytes**, and for
longer inputs the total output length is still right but the bytes from ciphertext offset 208
onward differ. A `UC_HOOK_MEM_WRITE` trace over `func#30`'s `sub sp, sp, #0x570` frame shows
writes landing **outside** that frame, which is consistent with a fixed ≈208-byte scratch
buffer in the CBC path being overrun. See §10 item 27 — this needs an on-device check before it
is called an exploitable stack overflow, but it does not affect any payload decoded in this
report (all were far below the limit).

### 11.4 `func#36` — key argument ignored, not `func#30`'s inverse

```
  #36(9834ed518cbc8fbe…, keyarg=b'')                -> b'\x07Q\xeeSc\xa1\xf5\xd8'
  #36(9834ed518cbc8fbe…, keyarg=b'0123456789ab')    -> b'\x07Q\xeeSc\xa1\xf5\xd8'
  #36(9834ed518cbc8fbe…, keyarg=b'\x00'×12)              -> b'\x07Q\xeeSc\xa1\xf5\xd8'
  #36(9834ed518cbc8fbe…, keyarg=b'\x00\x01…\x0a\x0b')      -> b'\x07Q\xeeSc\xa1\xf5\xd8'
  => identical for every key argument; and != b'hello', so it is not #30's inverse
```

The input was `func#30`'s ciphertext of `hello` (`9834ed518cbc8fbe9af3c6ecb75eb8c0`, re-derived
in §11.11(d)). Had `func#36` been the matching decryptor it would have returned `b'hello'`. It
returns 8 unrelated bytes.

**Revision 4 supersedes the "fixed internal key" reading** — see §11.11(a). `func#36` calls
`rijndael_setup` with `keylen = 32` (AES-256) and a user-key pointer into its own stack frame, so
there is no constant to recover; the 8 bytes above are the PKCS#7-unpadded AES-256-ECB decryption
of that one block under a key determined by the stack layout.

### 11.5 The constant key / nonce getters

Each was called three times with three different arguments. All four that run return the
**same value every time**:

```
  func#86   @0x10de0c -> ['5VEJK9Uk4d0elpVT']
        base64 -> 12 bytes e551092bd524e1dd1e969553
  func#159  @0x134d40 -> ['OVmx02wMFR6WaGtW']
        base64 -> 12 bytes 3959b1d36c0c151e96686b56
  func#160  @0x13571c -> ['V0V4V2pOa1ptZGsl']
        base64 -> 12 bytes 574578576a4e6b5a6d646b25
  func#161  @0x136134 -> ['xV2xKTlZsBUVk1He']
        base64 -> 12 bytes c55db1293959b015159351de
```

Two could not be run standalone and are reported honestly:

```
  func#87   @0x10df84 -> UC_ERR_FETCH_UNMAPPED / UC_ERR_READ_UNMAPPED
  func#90   @0x11044c -> heap exhausted
```

`func#87` needs a live `JNIEnv` (it is the `func#55` key provider and upcalls Java);
`func#90` allocates until the 4 MB emulated heap is gone. Neither failure changes any
conclusion — `func#86`'s value is what reaches `func#85` on the `func#54`/`func#55` path.

**Four independent 12-byte secrets, all argument-independent, all recoverable with one call
each.** 12 bytes is a GCM nonce length, not an AES key length, which is the strongest evidence
that the `func#157`/`func#158` context is `AES/GCM/NoPadding` with the 24-byte value from
`0x17428` as the key.

### 11.6 `func#157` / `func#158` — watching the key install happen

(a) every `bl func#193` inside the builders, captured at the callee's entry:

```
    func#157 sret -> b'\x00\x00\x00\x00\x00\x00\x00='
        bl func#193(src=0x17428, len=32, dst=0x81eff78)
        bl func#193(src=0x17448, len=16, dst=0x81eff60)
    func#158 sret -> b''
```

This matches the de-flattened CFG exactly (`work/analysis/deob/F157.txt`):

```asm
0x131d88:  adrp  x0, #0x17000 ; add x0, x0, #0x428   -> 0x17428   KEY_CT
0x131d94:  sub   x8, x29, #0x28                      -> dst
0x131d98:  mov   w1, #0x20                           -> len 32
0x131d9c:  bl    #0x14193c                           -> func#193
0x131da0:  adrp  x0, #0x17000 ; add x0, x0, #0x448   -> 0x17448   IV_CT
0x131da8:  sub   x8, x29, #0x40
0x131dac:  mov   w1, #0x10                           -> len 16
0x131db0:  bl    #0x14193c                           -> func#193
```

(b) the content those two blobs decode to (§11.1): a **24-byte key** and a **12-byte nonce**.

(c) the 16-byte stack slot is immediately recycled as the cipher-context struct — the ASCII
tail of the nonce survives at `+7`:

```
      slot[0] @0x81eff78 after func#157 = 310000000000000020000000000000004000201000000000
      slot[1] @0x81eff60 after func#157 = 78ff1e0800000000 30326547466c566d52 00000000000000
                                                     └── "02eGFlVmR" — the tail of
                                                          "WMVEwVG|02eGFlVmR"
```

`slot[0]` reads `0x31`, `0x20`, `0x10002040` — i.e. the context stores a length of **49**
(`0x31`, the 32-char key plus state) and **32** (`0x20`) alongside a pointer. `func#157`'s own
sret is 7 NUL bytes Base64'd; the `func#191` core returns zeros without a live `JNIEnv`, so
the **mode** (GCM) is inferred from the 24 B key + 12 B nonce pair and corroborated by the DEX
string `AES/GCM/NoPadding` — it is *not* claimed as executed.

### 11.7 `func#14` — the LibTomCrypt key schedule, dumped from memory

A hook on `0x32158` while running `func#85` gave the real prototype and the real struct:

```
  keylen=16  x0=0x81efb18 (skey)  x1=0x10001041 (userkey)  x2=0x16c10 (unused)  x3=0x10  x4=0x10
      *x1 = b'0123456789abcdef'   <- the key bytes verbatim
      *x2 = b'\x00eHBvc2Vk\x00BR'   <- NOT a table (0x16c10 is .rodata string data)
      round keys found at struct+0xc, stride 32, 11/11 rows == FIPS-197 (LE words): True
  keylen=24  … x3=0x18 …  13/13 rows == FIPS-197: True
  keylen=32  … x3=0x20 …  15/15 rows == FIPS-197: True
```

Three things this settles:

1. **No KDF.** `*x1` is the key string's bytes verbatim. Nothing hashes, stretches, truncates
   or pads them. Whatever 16/24/32-byte string reaches `func#85` *is* the AES key.
2. `x3` (and `x4`) carry the key length **in bytes**, and the round count follows
   `10 / 12 / 14` — the expanded schedule in memory has exactly `Nr+1` rows of 16 bytes at a
   32-byte stride, each row stored as four little-endian words.
3. `x2 = 0x16c10` is **not** a table. It points into plain ASCII `.rodata` and is never read.

### 11.8 All nine AES tables, regenerated and compared

```
  setup_Sbox  @0x128b0 == FIPS-197 S-box             : True
  setup_RSbox @0x139b0 == inverse S-box (S.index(i)) : True
  Te0         @0x118b0 == generated Te0              : True (256/256 words)
  Te1         @0x11cb0 == Te0 rotated right 1 byte   : True
  Te2         @0x120b0 == Te0 rotated right 2 byte   : True
  Te3         @0x124b0 == Te0 rotated right 3 byte   : True
  Td1         @0x12db0 == Td0 rotated right 1 byte   : True
  Td2         @0x131b0 == Td0 rotated right 2 byte   : True
  Td3         @0x135b0 == Td0 rotated right 3 byte   : True
  Td0         @0x129b0 first word = 0x51f4a750 (LibTomCrypt Td0[0]=0x51f4a750)
  setup_rc (Rcon) located by searching for [1,2,4,8,16,32,64,128,27,54,108,216,171,77] -> 0x13b10
      256 bytes there = 01020408102040801b366cd8ab4d9a2f ...
      LibTomCrypt extended Rcon (powers of 3 in GF(2^8)); OpenSSL ships only 10 entries.
  setup_log / setup_alog present anywhere in the file : False / False
```

That last line is the identification: **the 256-entry extended Rcon is LibTomCrypt-specific.**
OpenSSL's `aes_core.c` and mbedTLS both ship the short 10-entry `01 02 04 … 1b 36` table, and
no GF(2⁸) log/antilog permutation exists anywhere in the file — which is also what disproves
revision 1's `setup_log`/`setup_alog` claim (§10 item 22).

### 11.9 What was *not* proven dynamically

Stated explicitly so nothing is over-claimed:

| Claim | Status |
|---|---|
| `func#85` = AES-ECB/PKCS7/hex | **PROVEN** — 27/27 KATs + 20 000-byte inputs |
| `func#94` = exact inverse of `func#85` | **PROVEN** — round-trip on every KAT |
| `func#30` = AES-128-CBC, key 0, IV 0, key arg ignored | **PROVEN** — 5 keys × 5 plaintexts + 221-length sweep |
| `func#193` = XOR-`0x5A` decoder | **PROVEN** — 3 blobs, agrees with offline decode |
| `func#86/#159/#160/#161` return fixed 16-char Base64 | **PROVEN** — 3 args each, identical |
| AES tables are LibTomCrypt's | **PROVEN** — all 9 regenerated bit-for-bit |
| Round keys are FIPS-197 | **PROVEN** — dumped from the live struct, 11/13/15 rows |
| `0x17428` yields a 24-byte AES-192 key | **PROVEN** — decoded under emulation |
| `func#157/#158` implement **GCM** | **PROVEN NATIVE (rev 4), evidence corrected in rev 5** — no `javax/crypto`, `Cipher`, `AES/GCM`, `NoPadding`, `SecretKey`, `GCMParameterSpec`, `IvParameterSpec` or `doFinal` string exists anywhere in the `.so`, plain *or* Base64. The rev-4 supporting claim about `func#172` loading the S-box through GOT `0x1bb638`/`0x1bb640` is **withdrawn** — those slots point into `.bss` and `func#172` is an opaque predicate (§11.13). The `func#191` core still returns zeros without a live `JNIEnv` (§11.11) |
| `func#157/#158` plaintext path | **PARTIALLY RESOLVED (rev 4)** — a heap trace of a standalone `func#157` call shows it decoding `0x17428` and writing the XOR-`0x5A` result (the 32-char ASCII Base64 `At91IxVnRSbFppV0UxNFdUSnplTW5ONA`) to `heap+0x1120`, and *never* performing the Base64 → binary step; `func#158` does the same with `0x17458`. So under standalone emulation only key-material staging happens, which is consistent with the plaintext arriving from caller `func#57` (§11.11) |
| `func#36`'s key | **RESOLVED AS NOT-A-CONSTANT (rev 4)** — there is no fixed internal key to recover. `rijndael_setup` is entered with `keylen = 32` (AES-256) and a user-key pointer that lands inside `func#36`'s own stack frame, overlapping a local `std::string`; the bytes there are a function of the input length. That is why every static candidate (zero key, `0123456789abcdef`, MD5/SHA-1/SHA-256 KDFs, ECB and CBC, `iv = key[:16]`) failed. The output *is* deterministic for a given input and independent of the second argument (§11.11) |
| `func#87`'s returned key | **NOT RUN** — needs a live `JNIEnv` |
| The >220-byte `func#30` divergence | **OBSERVED, root cause unconfirmed** — see §10 item 27 |
| `0x15084` pin == `SHA-256`(APK signer cert DER) | **PROVEN** — byte-exact, two independent readers (§6.5B, `frida/clone_signer.py`) |
| `0x15084` has exactly one referrer (`func#245`) | **PROVEN** — inverted `data_refs` over all 1,090 functions (§10 item 30) |
| §2.2 slot → `func#51…#72` mapping | **PROVEN** — relocations ⋈ `funcmap.json` ⋈ DEX delegate bodies (§10 item 29) |
| §2.2A "which native calls which cipher" | **PROVEN** — direct-call edges only, no inference |
| TLS pin **values** handed to `CertificatePinner.Builder.add` | **NOT RECOVERED** — not a `.so` string constant; needs a live capture (§10 item 30) |
| Whether the forged `PackageInfo.signatures` actually satisfies `func#226` on a device | **NOT YET OBSERVED** — the hook is written and unit-verified against the real certificate bytes, but no phone run has happened (§11.10) |

### 11.10 The on-device harness (revision 3) — what was built and what was verified *without* a phone

§11.1–§11.9 were proven by executing the real code under Unicorn. Revision 3 turns that into a
deployable Frida agent, and — because no device was available in this environment — verifies
every part of it that *can* be verified offline. Stated plainly so nothing is over-claimed:
**the agent has not yet run against the live app.**

**Verified offline, against the real `libtopfollow.so` bytes:**

| Check | Result |
|---|---|
| `node frida/test_agent_offline.js` | **138 / 138 assertions pass** (78 in revision 3, +60 in revision 4: detection-token coverage decoded live out of the real `.so`, `filterMapsBuffer` length preservation, and the new reader offsets) |
| — the agent's pure-JS AES vs FIPS-197 (128/192/256, enc *and* dec) | 5/5 |
| — vs the 11 `func#85` vectors of §11.2 | 11/11 |
| — `func#94` round-trips | 5/5 |
| — vs the 5 `func#30` vectors of §11.3 | 5/5 |
| — `rpc.exports.decrypt` on real captured ciphertext | 5/5, incl. naming the verified key and never flagging a 16/24/32-byte key as a guess |
| — 3-layer `.rodata` secret decoding (`0x17428`, `0x17448`, `0x17458`, `0x161ca`) read out of the file | 4/4 |
| — AES table anchors (`Te0@0x118b0`, `Sbox@0x128b0`, `RSbox@0x139b0` = exact inverse, `Rcon@0x13b10`) | 4/4 |
| — all 22 `JNINativeMethod` slots rebuilt from `analysis/relocs.json` (`R_AARCH64_RELATIVE` addends; the file bytes at `0x1b2198` are **all zero**) and matched name+signature+`fnPtr` against `analysis/jni_natives.txt` | 22/22, and every `fnPtr` lands inside the RX segment |
| `rpc.exports.selfTest()` with the module mapped | **26 / 26 vectors pass, 0 skipped**, including the 6 live-memory `.rodata` reads and `SHA-256(original cert) == pin` — re-runnable with no device via **`frida/selftest_real_so.js`**, which backs `NativePointer.read*` with the real `.so` file and resolves `MOD` through the agent's own `findModule()` |
| `rpc.exports.signature()` against the real bytes | `liveBlob` = the 120-char plaintext blob read from `0x15084`, double-Base64-decoded to `d845591e…6bec5e`; `liveMatchesPin = true`; `originalCertSha256 == pinnedSha256`; `originalCertLen = 864` |
| `rpc.exports.signature()` | reads the 120-char blob live from `0x15084`, double-Base64-decodes it, and `liveMatchesPin == true` |
| `frida/clone_signer.py` | APK cert DER == embedded blob (864 B); `.so @0x15084` decodes to the pinned digest; clone cert reproduces subject/serial/validity/algorithm |
| `frida/repack_apk.py` on the real APK | 1,266 → 1,268 entries, **0 payload changes, 0 compression-method changes**, all 8 `.so` entries STORED and `data_offset % 4096 == 0`, APK Signing Block removed, `zipfile.testzip()` clean, androguard still parses it (`extractNativeLibs=false` preserved) |
| `frida/run_frida.py --offline-decrypt` | decrypts §11.3's order JSON back to `{"order_id":12345,"type":"follower"}` with no device attached |

**Design rules the agent enforces in code** (from §3.8 and §8 item 7):

1. Entry-only `Interceptor.attach` on every control-flow-flattened function. Registers are
   *read* in `onEnter`; nothing is written. `Interceptor.replace` is never used on `func#85`,
   `#94`, `#30`, `#36`, `#157`, `#158`, `#226`, `#73` or `#224`.
2. `Interceptor.replace` is available for the six small leaf detectors (`#200`, `#99`, `#162`,
   `#225`, `#169`) but is gated behind `CONFIG.stubDetection`, which is **`false` by default**
   even in `bypass` mode, because their return polarity is unproven and a wrong guess tells the
   app it *is* being analysed. `func#224` is deliberately excluded — it holds a reachable `b .`
   trap at `0x1576ac`.
3. `/proc/self/maps` hiding is done by tracking the fds the library opens on `/proc/...maps`
   and rewriting the **`read`/`__read_chk` buffer** in place, length-preserving, so the
   `read()` return value stays valid and no counter or register is patched. The `fgets` and
   `strstr` hooks are kept as defence in depth only — this library imports neither (item 39),
   so on TopFollow v8.4.5 they fire 0 times. Everything happens in libc, never inside the
   library's own flattened scanners.
4. The signature check is defeated by fixing its **Java input** (§6.5C), not by patching
   `func#226`.

**Not verified, and why:** no Android device or emulator was reachable from this environment,
`frida-server`/Gadget could not be executed, and the GitHub release CDN refused the
`frida-gadget-*-android-arm64.so.xz` download (HTTP 302 → TLS failure), so the Gadget binary is
not in the repository either. The first on-device step is therefore `rpc.exports.selfTest()`
followed by `rpc.exports.selfCalibrate()`: if `selfCalibrate` reports **22/22**, every offset in
this report is confirmed against the live mapping and the rest of the session can be trusted;
anything less means ASLR-independent drift (a different build) and the run should stop there.

---

### 11.11 Revision-4 probes — `func#36` resolved, GCM proven native, key-material staging

Four scripts were added under `work/analysis/` for this pass. All of them reuse the existing
`emu.py` Unicorn harness (relocations applied, libc/libc++ shimmed) and `aesdec.py`, a reference
AES **decryptor** written for this revision.

| Script | Purpose |
|---|---|
| `keyrec36.py` / `keyrec36b.py` | hook `func#14` (`rijndael_setup`) entry inside a `func#36` call and dump `x0..x4`, resolving `x1` as either a raw buffer or a libc++ long `std::string` |
| `f36_derive.py` | sweep input lengths 8…64 B and second-argument values, looking for a key derivation rule |
| `f36_stackkey.py` | determinism test + stack pre-fill test (does the caller control the key buffer?) |
| `aesdec.py` | reference AES-ECB/CBC decrypt + PKCS#7 unpad. Regenerates `Te0`/`Td0` from first principles and compares byte-for-byte with the `.so`'s tables at `0x118b0`/`0x129b0` (and `Td1..Td3` as right-rotations), so the reference and the binary are provably doing the same arithmetic |
| `gcm_material.py` | run `func#157`/`func#158` and search the heap for every stage of the key/nonce encoding chain |
| `f30_blob.py` | run `func#30` with a `func#14` hook and search the heap for the `0x1606a` blob |
| `b64_sweep.py` / `b64_all.py` / `blob_hunt.py` | enumerate every Base64-hidden C string in `.rodata` (1–3 layers, plus XOR-then-Base64) and map each address to the functions that reference it |
| `callees.py` | dump a function's direct callees and data refs with best-effort labels |

#### (a) `func#36` is AES-256-ECB decrypt + PKCS#7 unpad, keyed from its own stack frame

`func#14 @0x32158` is `rijndael_setup`: it is the only function in the library that references
`setup_Sbox @0x128b0` and `setup_rc @0x13b10`, and it is called by `func#30`, `func#36`,
`func#85` and `func#94` — i.e. every cipher in the library goes through it. Hooking its entry is
therefore a reliable "a key schedule is being built right now, with these arguments" signal.

Inside a `func#36` call the hook reports, for **every** input:

```
x0 (skey)    = 0x81efb20          <- stack
x1 (userkey) = 0x81efaf1          <- stack, 0x2f bytes below skey
x2           = 0x81efad9          <- stack (the unused .rodata ptr 0x16c10 case does not apply here)
x3 (keylen)  = 32                 <- AES-256, always
x4           = 16
```

`x1` is not a `.rodata` pointer and not a heap buffer — it is inside `func#36`'s own frame, and
the 32 bytes there overlap a local `std::string`. Their content tracks the *input length*, which
is why the key looked "fixed but unrecoverable" from the outside:

| input (raw bytes after hex-decode) | 32 bytes at `x1` |
|---|---|
| 8 B `a0a1a2a3a4a5a6a7` | `00×22 ‖ 10 ‖ a0a1a2a3a4a5a6a7` |
| 16 B `a0…af` | `00×22 ‖ 20 ‖ a0a1a2a3a4a5a6a7` |
| 32 B `a0…bf` | `00×22 ‖ 31 ‖ 0000000000000020` |
| 48 B | `00×22 ‖ 41 ‖ 0000000000000030` |
| 64 B | `00×22 ‖ 51 ‖ 0000000000000040` |

(The `31`/`41`/`51` bytes are the `((len+16) & ~15) | 1` capacity field of a libc++ long
`std::string`, and the following 8 bytes are its size field — the key buffer is reading straight
through that struct.)

Three controls establish that this is a genuine property of the code and not an emulator artefact:

1. **Determinism.** Three independent emulator instances, same input → byte-identical output
   `4b2335de40d86c66c2326952a93e9b03760a85269950de1919b6d82495483acd`.
2. **Caller-independent.** Six different second arguments (`b'k'`, `b'key'`, `b''`,
   `0123456789abcdef`, 40 × `A`, `bytes(range(16))`) → identical output. `arg1` is a decoy.
3. **Not stack residue.** Pre-filling 2 KB of the stack below `SP` with two different marker
   patterns changes nothing, and neither marker appears anywhere near `x1`. The key buffer is
   not reading leftover data from a previous call.

Semantics, from the same runs:

| input shape | observed behaviour |
|---|---|
| not valid lowercase hex (`hello`, `ZZZZ…`, raw bytes, `…efgg`) | returns empty, **`func#14` is never called** — the hex decode gates the whole function |
| hex-decoded length not a multiple of 16 (24 B) | output **equals the hex-decoded input verbatim** (echo) |
| multiple of 16, PKCS#7 valid after decrypt (64 B case) | output = 9 B = the unpadded plaintext, i.e. 55 bytes of `0x37` padding removed |
| multiple of 16, padding invalid | output = the full raw decrypted bytes |

So `func#36` is a **PKCS#7 padding oracle** whose key is a function of its own stack layout. It
is reachable from Java as `q.k (slot 15, func#71) → func#252 → func#36`, on the
`OkHttpClient`/`CertificatePinner` construction path. Two operational consequences:

* Its output cannot be reproduced offline from the binary alone, because the key is not a
  constant. Do not build a decryptor for it — hook it (`Interceptor.attach` entry+leave) instead.
  `frida/topfollow_agent.js` already hooks `func#36` entry-only for exactly this reason.
* Because it echoes its input when the padding is invalid and returns the unpadded plaintext when
  it is valid, it leaks one bit per call. Anything that can feed it a chosen hex string can use
  it as an oracle — which is the more interesting finding than the key.

#### (b) The GCM path is native — proven by absence of any Java crypto string

```
javax/crypto     plain: absent   Base64: absent
AES/GCM          plain: absent   Base64: absent
NoPadding        plain: absent   Base64: absent
Cipher           plain: absent   Base64: absent
SecretKey        plain: absent   Base64: absent
GCMParameterSpec plain: absent   Base64: absent
IvParameterSpec  plain: absent   Base64: absent
doFinal          plain: absent   Base64: absent
```

Earlier revisions listed GCM as *inferred* from the DEX string `AES/GCM/NoPadding`. That string
is in the DEX, not in the `.so`, and the `.so` contains no way to reach `javax.crypto` at all — so
the `func#157`/`func#158` contexts are a **native** GCM built on the same LibTomCrypt AES core:

```
q.v (#57, slot 6)  ─┬─> #157 ─> #193 (XOR 0x5A) ─┐
                    │        └─> #176 ─> #179/#180/#181/#182
                    │        └─> #177 ─> #191  <── GCM core
                    │        └─> #178 ─> #181/#192
                    └─> #158 ─> (same, minus #193)
q.b (#64, slot 13) ────> #157
q.p (#67, slot 16) ─┬─> #241 ─> #191          <- response handling also reaches the GCM core
                    └─> #178
                                      │
                    #191 ─> #79, #172, #173, #674, #682
                    #241 ─> #79, #172, #173, #674, #682   (identical callee set)
                              │
                    #172: adrp/ldr 0x1bb638 -> 0x1c28a0  (.bss CFF global)
                          adrp/ldr 0x1bb640 -> 0x1c2d2c  (.bss CFF global)
                          eor / and / mul, 149 insns, no calls, no PLT
                          == an MBA OPAQUE PREDICATE, always true -- NOT GF(2^128), NOT AES
```

**(revision 5 correction)** `func#172` is *not* the GF arithmetic core. Its two GOT loads resolve
to `.bss`, and its 149 instructions are the same `(v + ~k + k) * v == v²` / `w < 10` tautology that
opens `JNI_OnLoad`, `func#12` and every other flattened body. The claim that the GCM path is
**native** does not depend on it and still stands — it rests on the absence of every
`javax.crypto` string, plain or Base64, from the whole 1,805,400-byte `.so`. What the corrected
table scan does establish is stronger and simpler: **only five functions in the entire library
reference the Rijndael tables, and none of them is on the GCM path** (§11.13).

`func#191` still returns zeros for a standalone call without a live `JNIEnv`, so the GCM *plaintext*
is not recoverable offline; what is now proven is that the implementation is in the `.so`.

#### (c) Key-material staging: XOR-`0x5A` then **one** Base64 layer

`gcm_material.py` decodes each blob statically and then runs the builders, searching the
emulated heap for every stage:

| blob | raw `.rodata` | XOR `0x5A` | Base64 layer 1 | found on heap after running |
|---|---|---|---|---|
| `0x17428` (32 B) | `1b2e636b…6f15141b` | `At91IxVnRSbFppV0UxNFdUSnplTW5ONA` | `02df752315674526c5a695745313457544a7a654d6e4e340` (24 B) | `func#157`: XOR stage **yes** (`heap+0x1120`), Base64 stage no |
| `0x17448` (16 B) | `0d170c1f…360c3708` | `WMVEwVG02eGFlVmR` | `58c544c151b4d9e185955991` (12 B) | neither stage |
| `0x17458` (16 B) | `176a0c1f…2f0b301c` | `M0VEwVGt0aVJuQjF` | `334544c151add1a549b908c5` (12 B) | `func#158`: XOR stage **yes** (`heap+0x1120`), Base64 stage no |

Two things follow. First, the chain is `raw → XOR 0x5A → ASCII Base64 → b64decode → binary`, i.e.
**one** Base64 layer after the XOR — the 24/12-byte key and nonce values already published in §7
are correct, but the layer count in the earlier narrative was not. Second, the three sub-blobs are
**one contiguous 64-byte packed region `0x17428…0x17468`** (`0x17428 + 0x20 + 0x10 + 0x10`),
which a single `func#193` pass decodes; `func#157` references the key and nonce-1 offsets,
`func#158` references nonce-2. That the ASCII stage lands on the heap while the binary stage never
appears is the concrete form of the "`func#191` returns zeros without a `JNIEnv`" limitation.

Note the contrast with the signature-pin blob at `0x15084`, which is **plaintext double-Base64 with
no XOR layer** (§6.5, item 30). The library uses both conventions, so a decoder that assumes one
will silently miss the other.

#### (d) `func#30` re-verified, and its `0x1606a` reference is dead

`f30_blob.py` runs `func#30` with a `func#14` hook:

| `pt` | output | `rijndael_setup` args |
|---|---|---|
| `b''` | `0143db63ee66b0cdff9f69917680151e` | `keylen=16, key=00×16` |
| `b'a'` | `8e4a3d4beb92d54c7e95f67d41daed59…` | `keylen=16, key=00×16` |
| `b'hello'` | `9834ed518cbc8fbe9af3c6ecb75eb8c0` | `keylen=16, key=00×16` |
| `b'0123456789abcdef'` | 64 hex chars (two blocks) | `keylen=16, key=00×16` |
| 221 × `x` | 448 hex chars | `keylen=16, key=00×16` |

The key is `0^16` for every input and every second argument, the output is lowercase hex, and the
`b''` case is exactly `ECB_enc(0^16, 0^16)` — CBC with a zero IV degenerates to ECB on the first
block, which is an independent confirmation of both the mode and the zero key. The 16-char Base64
string `U0dKR01FNW9OV3h3` at `0x1606a` decodes in **two** layers to the 11 printable characters
`HbF0Nh5lp` (revision 4 wrongly printed the Base64 text's own bytes, `53474a474d45356f4e577877`,
as if they were the decoded value) — and it **never appears on the heap in any of these runs**: like `func#86`'s `0x17307` it sits
on an opaque-predicate path and must not be reported as `func#30`'s nonce.

#### (e) Code duplication is not one of the techniques

Hashing every recovered function body ≥ 64 B (1,090 functions) produces exactly **one** pair of
byte-identical bodies: `func#825` and `func#831`, 100 B each. Every CFF state machine, MBA
predicate and scanner is unique. `func#241` and `func#191` have the identical callee set
`{#79, #172, #173, #674, #682}` yet differ in 4,193 bytes — same role, independently obfuscated.
The practical consequence is that signature- or template-based deobfuscation cannot be amortised
across this library; each function has to be handled on its own.

---

### 11.12 Revision 4 — the detection layer rebuilt around how the library actually reads files

Item 39 invalidated the maps-hiding design that revisions 1–3 documented, so the agent's detection
layer was rebuilt and then verified offline against the real `.so` bytes.

#### (a) What the import table says

`work/analysis/funcmap.json` aggregates every PLT call site. The full table is **88 symbols**;
this is the file-IO and string subset that matters:

```
__open_2        8 call sites      read            3       memcmp          5
__read_chk      6 call sites      close           6       memchr          4
access          1 call site       strcmp          9       strlen         11
clock           1 call site       strcpy          2       __strlen_chk   13
inflate/init    1 + 1             syscall         2       dl_iterate_phdr 1

fopen   0     fgets 0     fclose 0     strstr 0     stat 0     lstat 0     opendir 0
```

Only three functions touch the read path, and they are shared by all four scanners:

```
func#99  (anti-Frida, XOR-0x37 tokens) ─┐
func#225 (maps integrity: rwxp/(deleted))┼─> func#129 @0x11deb0 ─┐
func#162 (anti-Frida, Base64 tokens) ───┼─> func#198 @0x143694 ─┼─> __open_2 + __read_chk/read + close
func#200 (anti-hook scan) ──────────────┘                        │
func#60  (179,828 B Xposed/Riru/Substrate scanner) ─> func#213 @0x151e68 ─┘
```

`func#129`, `func#198` and `func#213` have identical callee sets
(`{#23, #146, #147, #676, #693, #694, #695, #701, #1046}`) and identical PLT usage — they are the
same "read this path into a buffer" helper, cloned and independently obfuscated three times
(consistent with item 38: they are *not* byte-identical).

#### (b) The corrected hiding strategy

`hookMapsFiltering()` in `frida/topfollow_agent.js` now works in four steps:

1. **Track fds.** `__open_2`, `open`, `open64` and `openat` are hooked; any fd returned for a
   path matching `/proc/...` + `maps|smaps|task/` is added to a set.
2. **Rewrite the buffer.** `read`, `__read_chk`, `pread` and `pread64` are hooked. On return, if
   the fd is tracked, the buffer is split on `\n` and every suspicious line is replaced by
   `7f000000-7f001000 r--p 00000000 00:00 0` padded with spaces **to exactly the same byte
   length**. Length preservation is what makes this safe: `read()`'s return value stays correct,
   no counter, register or flattened body is touched, and the scanner's own line splitter still
   sees a well-formed file.
3. **Stop tracking on `close`.**
4. **Entry-only watches** on `func#129`, `func#198`, `func#213` and `func#60` — log-only, never
   `Interceptor.replace`, because all four are control-flow-flattened.

The `fgets` and `strstr` hooks are retained but demoted to defence in depth with an explicit note
that this library imports neither, so on TopFollow v8.4.5 they fire zero times. The `strstr`
suppression was also tightened to **exact token matches of length ≥ 6**: `'libc.so'` and
`'libart.so'` are legitimate substrings of half the lines in a real maps file, so suppressing them
by substring would shred the file — which is itself a far louder signal than the token.

#### (c) The token list is now generated from the binary and asserted against it

`MAPS_NOISE` grew from 17 to 30 entries and is grouped by owning function (item 40's table). The
important part is that it can no longer drift: `frida/test_agent_offline.js` §10 re-derives the
tokens **from the real `libtopfollow.so` bytes** at test time —

* scans `.rodata` (`0x13000…0x1c000`) for NUL-delimited C strings that are valid Base64,
* decodes up to three layers with a **strict** hand-rolled decoder (Node's
  `Buffer.from(x,'base64')` is lenient and silently skips invalid characters, which produces
  phantom decodes — that cost a false pass before the rewrite),
* asserts that each of the 16 detection tokens really is present in the binary in Base64 form, and
* asserts that each one is covered by `MAPS_NOISE`.

The same section asserts the request/response evidence decodes: `https://i.instagram.com/api/v2/`
(3 layers, `0x159ec`), `https://www.instagram.com/` (2 layers, `0x15c02`), `create_note/v2/`
(3 layers, `0x14bf4`), `seen/` (3 layers, `0x16b60`), `/save/` (2 layers, `0x14de8`) and the
signature pin `d845591e…6bec5e` (2 layers, `0x15084`).

§11 then exercises `filterMapsBuffer` on a synthetic 8-line maps chunk containing
`libfrida-gadget`, `frida-gum-js-loop`, `rwxp`, a `riru_core/libbridge.so` path,
`libcso_substrate.so`, `/memfd:jit-cache (deleted)` and `libart.so (deleted)`, plus two innocent
lines. It asserts: ≥5 lines rewritten, **total buffer length unchanged**, **line count unchanged**,
all seven tokens gone, both innocent lines byte-identical, and that a chunk with no `\n` (a partial
line, as `read()` legitimately produces) is left completely alone.

#### (d) Result

| Check | Before rev 4 | After rev 4 |
|---|---|---|
| `node frida/test_agent_offline.js` | 78 / 78 | **138 / 138** |
| maps filtering actually intercepts this library's reads | **no** — `fgets`/`strstr` are not imported | yes — `__open_2`/`read`/`__read_chk` are |
| detection tokens covered | 17 hand-picked literals | 30, generated from item 40's table and asserted against the binary every test run |
| `func#60` (179,828 B scanner) | not watched | entry-only watch |
| reader helpers `#129`/`#198`/`#213` | unknown | entry-only watch, addresses in `OFF` |

Still **not** verified on a device: no phone or emulator was reachable, so none of these hooks has
run against the live app. The first on-device step is unchanged — `rpc.exports.selfTest()` then
`rpc.exports.selfCalibrate()`; if `selfCalibrate` does not report **22/22**, stop.

---

### 11.13 Revision 5 — the complete native AES chain, `JNI_OnLoad` instruction by instruction, and the real Base64 string layer

Everything in this section was re-derived from the file in this revision. Three things changed:
the AES implementation is now resolved down to the individual block primitive, `JNI_OnLoad` has
been fully disassembled for the first time, and the string-hiding layer turns out to be **larger
and more layered** than revision 4 described. One revision-4 claim is withdrawn (§11.11(b)).

#### (a) All eleven Rijndael tables, their exact addresses, and the five functions that touch them

The `.rodata` section starts at `0x118b0` and its **first 8,960 bytes are the LibTomCrypt AES
table set** — the cipher's tables are the very first thing in the read-only segment:

| table | address | bytes | first word (LE) | first 8 bytes | identity |
|---|---|---|---|---|---|
| `Te0` | `0x118b0` | 1,024 | `0xc66363a5` | `a5 63 63 c6 84 7c 7c f8` | LibTomCrypt `Te0[0]` ✔ |
| `Te1` | `0x11cb0` | 1,024 | `0xa5c66363` | `63 63 c6 a5 7c 7c f8 84` | `Te0` rotated right 1 byte ✔ |
| `Te2` | `0x120b0` | 1,024 | `0x63a5c663` | `63 c6 a5 63 7c f8 84 7c` | `Te0` rotated right 2 bytes ✔ |
| `Te3` | `0x124b0` | 1,024 | `0x6363a5c6` | `c6 a5 63 63 f8 84 7c 7c` | `Te0` rotated right 3 bytes ✔ |
| `setup_Sbox` | `0x128b0` | 256 | — | `63 7c 77 7b f2 6b 6f c5` | FIPS-197 S-box, byte-identical ✔ |
| `Td0` | `0x129b0` | 1,024 | `0x51f4a750` | `50 a7 f4 51 53 65 41 7e` | LibTomCrypt `Td0[0]` ✔ |
| `Td1` | `0x12db0` | 1,024 | `0x5051f4a7` | `a7 f4 51 50 65 41 7e 53` | `Td0` rotated right 1 byte ✔ |
| `Td2` | `0x131b0` | 1,024 | `0xa75051f4` | `f4 51 50 a7 41 7e 53 65` | `Td0` rotated right 2 bytes ✔ |
| `Td3` | `0x135b0` | 1,024 | `0xf4a75051` | `51 50 a7 f4 7e 53 65 41` | `Td0` rotated right 3 bytes ✔ |
| `setup_RSbox` | `0x139b0` | 256 | — | `52 09 6a d5 30 36 a5 38` | inverse S-box, `S.index(i)` for all 256 ✔ |
| `setup_rc` (Rcon) | `0x13b10` | 256 | — | `01 02 04 08 10 20 40 80` | **extended** Rcon: powers of 3 in GF(2⁸), 256 entries — OpenSSL ships only 10 |

`0x118b0 … 0x13c10` is therefore one contiguous 8,960-byte AES table block. `setup_log` and
`setup_alog` (the `gf_mult` slow tables some LibTomCrypt builds ship) are **absent** — this build
uses the `Te`/`Td` fast path only.

Re-scanning `.text` **function by function**, resetting the `adrp` page register at each function
entry (the whole-`.text` scan used in revision 4 let a page value survive a `bl`, which produced
false positives in whatever function happened to be laid out next), gives exactly **five**
functions that reference any of those tables:

| function | address | size | tables referenced (site count) |
|---|---|---|---|
| `func#10` | `0x2dc00` | 3,988 | `Te0 Te1 Te2 Te3 Sbox` (1 each) |
| `func#11` | `0x2eb94` | 4,664 | `Td1 Td2 Td3 Sbox RSbox` (1 each) |
| `func#12` | `0x2fdcc` | 4,428 | `Te0 Te1 Te2 Te3 Sbox RSbox` (1 each) |
| `func#13` | `0x30f18` | 4,672 | `Td1 Td2 Td3 Sbox RSbox×2` |
| `func#14` | `0x32158` | 8,908 | `Sbox×2 RSbox×2` |

No other function in the 1,090-function library touches them. In particular **`func#172` does
not**, and neither does `func#191` or `func#241` — see §11.11(b) for the withdrawn claim.
`work/analysis/aes_table_xrefs.json` holds every site address.

#### (b) The layer cake, with every layer proven by execution

```
JNI natives (Java-visible)
  q.o q.n q.i q.c q.r q.s q.m q.t q.u q.a q.v   ->  func#85   aes_ecb_encrypt_hex
  q.n q.i q.c                                    ->  func#94   aes_ecb_decrypt_hex
  q.i q.c q.r q.t q.m q.v q.p                    ->  func#30   aes128_cbc_zerokey_hex
  q.k                                            ->  func#252 -> func#36  aes256_ecb_decrypt+unpad
        |
        v
  func#85 (0x10c470, 6,556 B)  ECB encrypt, PKCS#7 pad, lowercase hex out
  func#94 (0x110b70, 9,140 B)  ECB decrypt, hex in, PKCS#7 unpad
  func#30 (0x38fa4,  4,508 B)  CBC encrypt, key = 0^16, IV = 0^16, hex out
  func#36 (0x3a838,  1,708 B)  AES-256 ECB decrypt + unpad, key = own stack frame
        |
        +-- all four call --> func#14 (0x32158) rijndael_setup(skey*, userkey*, unused, keylen, 16)
        |
        +-- #85, #30 -----> func#15 (0x34424) cbc_encrypt(cbc*, pt, ct, len, cipher_idx)
        +-- #94, #36 -----> func#16 (0x35518) cbc_decrypt(cbc*, ct, pt, len, cipher_idx)
                                  |
                                  +-- #15 --> func#12 (0x2fdcc) ECB encrypt block, dispatcher
                                  |             +--> func#10 (0x2dc00) Nr-specific leaf
                                  +-- #16 --> func#13 (0x30f18) ECB decrypt block, dispatcher
                                  |             +--> func#11 (0x2eb94) Nr-specific leaf
                                  +-- #16 --> func#12   (four more BL sites: the same
                                                         Nr-dispatch shape on the decrypt side)
```

The BL-site counts are from `work/analysis/xrefs.json` and are exact:

| primitive | address | BL sites | called from |
|---|---|---|---|
| `func#14` `rijndael_setup` | `0x32158` | 4 | `0x3a00c` (`#30`), `0x3aa24` (`#36`), `0x10d374` (`#85`), `0x111ed8` (`#94`) |
| `func#15` `cbc_encrypt` | `0x34424` | 2 | `0x3a024` (`#30`), `0x10d38c` (`#85`) |
| `func#16` `cbc_decrypt` | `0x35518` | 2 | `0x3aa3c` (`#36`), `0x111ef0` (`#94`) |
| `func#12` ECB enc block | `0x2fdcc` | 5 | `0x3488c` (`#15`); `0x34bb8` `0x34e40` `0x35418` `0x35768` (all `#16`) |
| `func#13` ECB dec block | `0x30f18` | 2 | `0x35948` `0x35bb0` (both `#16`) |
| `func#10` | `0x2dc00` | 2 | `0x3014c` `0x30310` (both `#12`) |
| `func#11` | `0x2eb94` | 1 | `0x31f44` (`#13`) |

Two facts follow that revision 4 did not state. **First, `func#85` is not really "ECB"** — it
routes through `cbc_encrypt` with a zero IV, which for the first block is bit-identical to ECB and
for later blocks is *not*; that is exactly why `func#85(b'0123456789abcdef')` returns 64 hex chars
whose **first** 32 are `69c4e0d86a7b0430d8cdb78070b4c55a` (the FIPS-197 AES-128 ciphertext of the
FIPS-197 plaintext under the FIPS-197 key) — reproduced again in this revision:

```
func#85(pt = 00112233445566778899aabbccddeeff, key = 000102…0f)
  -> 69c4e0d86a7b0430d8cdb78070b4c55a 954f64f2e4e86e9eee82d20216684899
     \______________ block 1 = ECB(K, PT), FIPS-197 C.1 ______________/
                                          \____ block 2 = the PKCS#7 pad block ____/
```

`func#30` is the same construction with the key forced to `0^16`, which is why `func#30(b'')` =
`0143db63ee66b0cdff9f69917680151e` = `ECB(0^16, 0x10 × 16)`. **Second, the CBC layer is a real,
separate, reachable primitive**, so any capture that only hooks `#85/#94/#30/#36` sees the hex
strings but not the per-block IV chaining; `frida/topfollow_capture.js` now hooks `#14`, `#15`,
`#16`, `#12` and `#13` as well (§9).

Known-answer results re-run in this revision (Unicorn, real machine code, `.init_array` untouched):

| call | result | verdict |
|---|---|---|
| `func#14(skey, 000102…0f, –, 16, 16)` | round keys at `skey+0x0c`, stride 32, 11 rows | == FIPS-197 ✔ |
| `func#14(skey, 000102…17, –, 24, 16)` | 13 rows | == FIPS-197 ✔ |
| `func#14(skey, 000102…1f, –, 32, 16)` | 15 rows | == FIPS-197 ✔ |
| `func#15(cbc, PT, ct, 16, 0)` | `ct = 69c4e0d86a7b0430d8cdb78070b4c55a` | == FIPS-197 C.1 ✔ |
| `func#16(cbc, CT, pt, 16, 0)` | `pt = 00112233445566778899aabbccddeeff` | inverse of C.1 ✔ |
| `func#85(PT, K)` | first block `69c4e0d8…c55a` | ✔ |
| `func#94(hex(CT), K)` with a *padded* input | `hex(PT)` | ✔ (a bare 16-byte block unpads to nothing and returns `null`) |

`cbc*` is a `LibTomCrypt symmetric_CBC` laid over a `symmetric_key`: the code inside `func#12`,
`func#13`, `func#15` and `func#16` reads `x0+8` (the `Nr` byte of the embedded key schedule),
`x0+0x3d0`, `x0+0x3d4`, `x0+0x438` and `x0+0x458` — and `sizeof(LTC symmetric_key)` for AES is
`4 + 8 + (14+1)·2·16·4 = 0x462`, padded to `0x468`, so `0x3d4`/`0x438`/`0x458` are precisely the
`CBC.IV`, `CBC.ct` and `CBC.pt` members. This is LibTomCrypt's `cbc_encrypt` / `cbc_decrypt` /
`rijndael_ecb_encrypt` / `rijndael_ecb_decrypt` / `rijndael_setup`, flattened and MBA-obfuscated.

The `Nr`-keyed `switch` inside LibTomCrypt's block functions is why there are *pairs*: `func#12`
is the dispatcher that also owns table references, `func#10` is one `Nr`-specific body reached from
it (`0x3014c`, `0x30310`), and symmetrically `func#13` → `func#11`.

#### (c) `JNI_OnLoad` disassembled — the three JNI calls, their exact table indices, and the `RegisterNatives` site

`func#50 @ 0x3e1d4` (2,272 bytes) **is** `JNI_OnLoad` — it is the library's only export. Its whole
body is a flattened state machine, but it makes exactly three indirect calls and they are now
pinned down:

```
0x03e1d4  sub  sp, sp, #0xb0                    ; canary prologue (mrs tpidr_el0 / ldr [x9,#0x28])
0x03e200  adrp x22, #0x1ba000                   ; --- CFF opaque predicate #1 ---
0x03e204  ldr  x22, [x22, #0xb50]               ;   GOT 0x1bab50 -> .bss state global
0x03e20c  adrp x23, #0x1ba000
0x03e210  ldr  x23, [x23, #0xb58]               ;   GOT 0x1bab58 -> .bss state global
0x03e220  ldr  w8,  [x22]                       ;   v = *g1 ; w = *g2
0x03e224  mov  w10, #0xf2e9 ; movk #0x52d3,lsl16 ;   k = 0x52d3f2e9
0x03e22c  mvn  w9, w10 ; add w9, w8, w9 ; add w9, w9, w10    ; (v + ~k + k) == v
0x03e238  ldr  w10, [x23] ; mul w8, w9, w8      ;   v*v
0x03e240  eor  w9, w8, #0xfffffffe ; tst w9, w8 ; cset w8, eq ;  (v*v) ^ ~1 == 0  ->  v == 0 or 1
0x03e24c  cmp  w10, #0xa ; cset w8, lt          ;   w < 10
          ...  always true  -> the dispatcher takes the real path ...

0x03e2f0  ldr  x8, [x19]                        ; x19 = the JavaVM* argument
0x03e300  ldr  x8, [x8, #0x30]                  ; JNI InvokeInterface, index 30/8 = 6
0x03e2f4  mov  w2, #6 ; movk w2, #1, lsl #16    ;   w2 = 0x00010006 = JNI_VERSION_1_6
0x03e2f8  sub  x1, x29, #0x10                   ;   &env
0x03e308  blr  x8                               ; (*vm)->GetEnv(vm, &env, JNI_VERSION_1_6)
0x03e318  stur w0, [x29, #-0x14]                ;   rc

0x03e84c  ldr  x0, [sp, #0x18]                  ; env
0x03e850  adrp x1, #0x14000 ; add x1, x1, #0xda2 ;  "com/nivaroid/topfollow/helper/q"  @0x14da2
0x03e85c  ldr  x8, [x8, #0x30]                  ; JNINativeInterface, index 30/8 = 6
0x03e860  blr  x8                               ; (*env)->FindClass(env, "com/nivaroid/topfollow/helper/q")
0x03e874  str  x0, [sp, #0x28]                  ;   jclass

0x03e920  ldr  x8, [x21]                        ; env
0x03e930  ldr  x8, [x8, #0x6b8]                 ; JNINativeInterface, index 0x6b8/8 = 215
0x03e924  adrp x2, #0x1b6000 ; add x2, x2, #0x198 ;  x2 = 0x1b6198  <-- the JNINativeMethod table
0x03e928  mov  w3, #0x16                        ;   nMethods = 22
0x03e92c  mov  x0, x21 ; mov x1, x22            ;   env, jclass
0x03e93c  blr  x8                               ; (*env)->RegisterNatives(env, cls, table @0x1b6198, 22)
          (a second, identical block sits at 0x03e96c..0x03e988 — the CFF duplicate)

0x03ea78  ldur w0, [x29, #-0x1c]                ; return JNI_VERSION_1_6
0x03eab0  bl   0x1b1c30                         ; __stack_chk_fail on the canary path
```

So: `GetEnv(JNI_VERSION_1_6)` → `FindClass("com/nivaroid/topfollow/helper/q")` →
`RegisterNatives(cls, 0x1b6198, 22)` → `return 0x10006`. Nothing else. There is no
`Java_...`-style dynamic lookup anywhere, no second class, and no anti-debug work in `JNI_OnLoad`
itself — that lives in the natives it registers.

The table at `0x1b6198` is a **static** `JNINativeMethod[22]` in `.data.rel.ro`
(`0x1b6160…0x1ba5f0`; note the section's file offset is `0x1b2160`, i.e. address minus `0x4000`).
All 528 bytes are **zero in the file** and are filled by **66 `R_AARCH64_RELATIVE` relocations**
(`0x1b6198…0x1b63a0`), which is why any static read of the table without applying relocations sees
nothing. `0x1b6198` has exactly **two** code references, both inside `JNI_OnLoad` — the table is
used once and never again.

#### (d) The 22 natives: randomised names, sorted in the DEX, and the exact `q.a … q.v` mapping

The `name` field of every table entry points at a plaintext C string in `.rodata` of the form
`x00` + six lowercase hex digits. All 22 exist, and each is referenced by exactly one relocation —
its own table slot:

| slot | DEX wrapper | native name (`.rodata` addr) | signature | `fnPtr` | = `func#` | size | crypto/detection reached (direct BL only) |
|---|---|---|---|---|---|---|---|
| 0 | `q.j` | `x0011a4c2` (`0x15315`) | `()J` | `0x3eab4` | `#51` | 1,408 | `#73` |
| 1 | `q.e` | `x0014e2e9` (`0x15b2c`) | `()Ljava/lang/String;` | `0x3f034` | `#52` | 916 | — |
| 2 | `q.d` | `x0016d3b9` (`0x16607`) | `()Ljava/lang/String;` | `0x3f3c8` | `#53` | 704 | — |
| 3 | `q.o` | `x0012d3e0` (`0x161db`) | `(Ljava/lang/String;)Ljava/lang/String;` | `0x3f688` | `#54` | 6,788 | `#85` `#86` `#87` |
| 4 | `q.n` | `x0011e28b` (`0x1547c`) | `(Ljava/lang/String;)Ljava/lang/String;` | `0x4110c` | `#55` | 9,388 | `#94` `#86` `#87` |
| 5 | `q.i` | `x00120b1e` (`0x16cca`) | `(Lcom/google/gson/JsonObject;Ljava/lang/String;)V` | `0x435b8` | `#56` | 47,808 | `#94` `#30` `#87` |
| 6 | `q.v` | `x0012e5a1` (`0x16b3a`) | `(Lcom/google/gson/JsonObject;)V` | `0x4f078` | **`#57`** | **160,912** | `#85` `#30` `#153` `#154` `#157` `#158` `#159` `#160` `#161` `#162` `#200` `#73` |
| 7 | `q.u` | `x00135e2a` (`0x16cd4`) | `(JsonObject;InstagramAccount;String)V` | `0x76508` | `#58` | 37,668 | `#85` |
| 8 | `q.c` | `x00105e9b` (`0x1705c`) | `(Ljava/lang/String;)Ljava/lang/String;` | `0x7f82c` | `#59` | 9,260 | `#30` |
| 9 | `q.r` | `x0015b1e9` (`0x1685d`) | `(JsonObject;String;String)V` | `0x81c58` | **`#60`** | **179,828** | `#85` `#30` `#153` `#204` `#21` |
| 10 | `q.t` | `x0015a3b7` (`0x15ed0`) | `(JsonObject;InstagramAccount;Order;)V` | `0xadacc` | `#61` | 73,008 | `#30` `#153` `#200` `#204` |
| 11 | `q.s` | `x0017b62c` (`0x15b36`) | `(String;String;String;)Ljava/lang/String;` | `0xbf7fc` | `#62` | 28,584 | `#85` |
| 12 | `q.m` | `x0011f42b` (`0x16a45`) | `()Ljava/lang/String;` | `0xc67a4` | `#63` | 22,280 | `#30` |
| 13 | `q.b` | `x0012f5b7` (`0x16a4f`) | `()Ljava/lang/String;` | `0xcbeac` | `#64` | 34,812 | `#157` (GCM ctx) |
| 14 | `q.a` | `x0014b4f3` (`0x16867`) | `(Ljava/lang/String;)Ljava/lang/String;` | `0xd46a8` | `#65` | 14,912 | `#85` `#159` `#160` `#161` `#162` |
| 15 | `q.h` | `x0011f1a2` (`0x16400`) | `(Lcom/nivaroid/topfollow/models/Order;)Ljava/lang/String;` | `0xd80e8` | `#66` | 33,020 | — |
| 16 | `q.p` | `x0015e49c` (`0x16871`) | `(Lretrofit2/Response;Order;InstagramAccount;)Ljava/lang/String;` | `0xe01e4` | **`#67`** | **117,628** | `#85` `#30` `#225` `#226` `#241`(→GCM) `#21` |
| 17 | `q.f` | `x0010e27f` (`0x162d7`) | `()Ljava/lang/String;` | `0xfcd60` | `#68` | 688 | — |
| 18 | `q.g` | `x00113f7a` (`0x16a59`) | `()Ljava/lang/String;` | `0xfd010` | `#69` | 1,328 | — |
| 19 | `q.q` | `x0014c1f9` (`0x1687b`) | `(Lretrofit2/Response;)Ljava/lang/String;` | `0xfd540` | `#70` | 3,368 | — |
| 20 | `q.k` | `x00126f7c` (`0x15da9`) | `(ZLjava/lang/String;)Lretrofit2/Retrofit;` | `0xfe268` | **`#71`** | 12,624 | `#252`(→`#36`) `#253` `#254` |
| 21 | `q.l` | `x0018d3f7` (`0x15334`) | `(I)Lretrofit2/Retrofit;` | `0x1013b8` | `#72` | 10,016 | `#254` |

The wrapper column is not inferred: it is the `invoke-static` target inside each of the 22 public
one-line methods of `com.nivaroid.topfollow.helper.q`, read out of `classes.dex` with androguard.
The class contains exactly **22 public static wrappers `a`…`v` plus exactly 22 `private static
native` methods**, and each wrapper delegates to exactly one native.

Three properties of the naming scheme are worth recording because they decide how you hook it:

1. **The names are randomised per build.** They carry no offset, no hash and no checksum:
   `int(name[1:], 16) - fnPtr` is a different value for all 22 slots (`0xdba0e`, `0x10f2b5`,
   `0x12dff1`, …), so nothing can be recomputed from the address.
2. **In the DEX they are sorted ascending** (`x00105e9b` < `x0010e27f` < … < `x0018d3f7`), because
   DEX method lists are ordered by name. In the `.so`'s `RegisterNatives` table they are **not**
   sorted — the table is in `q.a … q.v`-independent registration order. The mapping therefore has
   to be recovered by name, never by position, and `frida/test_capture_offline.js` asserts all 22
   name/signature/`fnPtr` triples against the relocated table.
3. **The names are plaintext in both files**, so the obfuscation buys nothing against anyone who
   can read either one; it only defeats *guessing* (`Java_com_nivaroid_topfollow_helper_q_a` does
   not exist). One of them, `x0015b1e9` at `0x1685d`, additionally has a direct `adrp+add`
   reference from `func#760` (`0x198c18`), i.e. the library reads its own native name at runtime.

#### (e) The string layer is bigger than revision 4 said: 21 Base64 blobs, up to **four** layers deep

`func#17 @ 0x35d58` is `std::string::basic_string(const char*)` — 460 bytes, **188 BL sites**, and
executing it proves it: `func#17(out, 0x15db5)` returns the `std::string` `"L3Byb2Mvc2VsZi9tYXBz"`,
i.e. the *Base64 text*, not the decoded value. `func#23 @ 0x3820c` (428 bytes, **371 BL sites**) is
the matching empty-`std::string` constructor.

`func#21 @ 0x3712c` (3,636 bytes, **43 BL sites**, 13 distinct callers) is the Base64 → `std::string`
decoder. Its call sites are unambiguous — `func#162` at `0x136e1c`:

```
0x136e1c  adrp x1, #0x15000 ; add x1, x1, #0xdb5   ; "L3Byb2Mvc2VsZi9tYXBz"
0x136e14  sub  x0, sp, #0x20  ; mov sp, x0         ; a fresh std::string on the stack
0x136e24  bl   0x35d58                             ; func#17: build std::string(b64 text)
0x136e30  mov  x0, x25 ; mov x8, x27
0x136e34  bl   0x3712c                             ; func#21: Base64-decode it
0x136e38  ldrb w8, [x25]                           ; ...and immediately use the result
```

and `func#245` at `0x16bc04`, which builds a `std::string` from `0x15084` — the 120-char signature
pin — and passes it to `func#21` twice, matching the pin's two Base64 layers. `func#21` does not
run to completion under standalone emulation (it needs the caller's live frame), which is why it is
**observed** here rather than executed; `frida/topfollow_capture.js` hooks it and logs its decoded
`std::string` return, so one run on a device settles every layer empirically.

Decoding every Base64-shaped NUL-terminated token in `.rodata` (`0x118b0…0x1ab5b`, 1,585 tokens)
recursively gives **21** blobs. This supersedes the 39-string table of item 40 — several entries
there were counted per *layer* rather than per blob, and the layer counts below are new:

| `.rodata` addr | stored text | layers | fully decoded | used by |
|---|---|---|---|---|
| `0x15084` | `WkRnME5UVTVNV1V3T0RZd016TmhPVEF6…` (120 ch) | **2** | `d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e` | `#245` ← `#226` ← `#67` (signature pin) |
| `0x14eae` | `V1ZWb1UwMUhUa2xVVkZwTlpWUm5PUT09` | **4** | `https://` | base-URL builder |
| `0x14bf4` | `V1ROS2JGbFlVbXhZTWpWMlpFZFZkbVJxU1hZPQ==` | **3** | `create_note/v2/` | endpoint path |
| `0x16b60` | `WXpKV2JHSnBPRDA9` | **3** | `seen/` | endpoint path |
| `0x14de8` | `TDNOaGRtVXY=` | **2** | `/save/` | endpoint path |
| `0x1606a` | `U0dKR01FNW9OV3h3` | **2** | `HbF0Nh5lp` | `func#30` — **dead**, opaque-predicate path |
| `0x15de3` | `WVVoU01HTklUVFpNZVRrelpETmpkV0ZYTlhwa1IwWnVZ…` (96 ch) | **3** | `https://www.instagram.com/graphql/query` | `#242` |
| `0x159ec` | `WVVoU01HTklUVFpNZVRsd1RHMXNkV016…` (80 ch) | **3** | `https://i.instagram.com/api/v2/` | `#244` |
| `0x15c02` | `YUhSMGNITTZMeTkzZDNjdWFXNXpkR0ZuY21GdExtTnZiUzg9` | **2** | `https://www.instagram.com/` | `#255` |
| `0x15db5` | `L3Byb2Mvc2VsZi9tYXBz` | 1 | `/proc/self/maps` | `#60`, `#162`, `#225` |
| `0x15541` | `bGliYnJpZGdlLnNv` | 1 | `libbridge.so` | `#60` |
| `0x156e8` | `bGliY3NvX3N1YnN0cmF0ZQ==` | 1 | `libcso_substrate` | `#60` |
| `0x15dd4` | `c3Vic3RyYXRl` | 1 | `substrate` | `#60`, `#162` |
| `0x16204` | `ZWR4cG9zZWQ=` | 1 | `edxposed` | `#60` |
| `0x167a9` | `bHNwb3NlZA==` | 1 | `lsposed` | `#60` |
| `0x16c11` | `eHBvc2Vk` | 1 | `xposed` | `#60` |
| `0x1607f` | `cmUuZnJpZGEuc2VydmVy` | 1 | `re.frida.server` | `#162` |
| `0x161eb` | `Z3VtLWpzLWxvb3A=` | 1 | `gum-js-loop` | `#162` |
| `0x16d97` | `bGliZnJpZGEtZ2FkZ2V0` | 1 | `libfrida-gadget` | `#162` |
| `0x16b75` | `bGliYXJ0LnNvIChkZWxldGVkKQ==` | 1 | `libart.so (deleted)` | `#225` |
| `0x16f69` | `bGliYy5zbyAoZGVsZXRlZCk=` | 1 | `libc.so (deleted)` | `#225` |

`work/analysis/b64_rodata_full.json` holds the machine-readable version, including the whole decode
chain for each blob. Note the split: **every detection token and every endpoint is Base64**, while
`riru`, `ygsik` and `rwxp` (item 40) are *plaintext* — the library mixes the two conventions inside
the same scanner, so an allowlist built from only one of them leaks. And the `0x159ec` / `0x15c02` /
`0x15de3` endpoints are **not** plaintext in the file as revision 4's §7 table implied; each is at
least two Base64 layers deep, with `0x14eae` four.

Two further `.rodata` facts from this revision: the ASCII string `AES` at `0x14b31` is the **only**
occurrence of that cipher's name anywhere in `.rodata` (no `rijndael`, no lowercase `aes`), and the
22 JNI signatures themselves are stored as plain C strings starting at `0x14b35`
(`(Lretrofit2/Response;)Ljava/lang/String;`) and `0x14b5e` (`(ZLjava/lang/String;)Lretrofit2/Retrofit;`)
— they are what the `RegisterNatives` table's `signature` fields point at.

#### (f) What is still *not* resolved

| question | status |
|---|---|
| Is `func#191` really GHASH/GCM, and where is its GF(2¹²⁸) multiply? | **Open.** It references no AES table (§11.13(a)) and returns zeros without a live `JNIEnv`. The native-GCM conclusion still rests on the absence of every `javax.crypto` string, plain or Base64 |
| `func#21`'s exact signature and whether it loops over layers | **Observed at call sites, not executed.** Needs a device: `topfollow_capture.js` hooks it and logs the returned `std::string` |
| `func#36`'s key | **Not a constant** (rev 4). The key buffer is a slice of its own stack frame; hook `#14` from inside `#36` to capture it per call |
| `func#7` (252 B, called by `#30 #36 #85 #94`) and `func#9` (1,148 B, called by `#15 #16`) | **Unidentified** shared leaves; no table, no PLT crypto import |
| Anything on a real device | **Nothing has ever run on a phone or emulator.** Every result above is from the file, via Unicorn or static decode |

---

*End of report.*
