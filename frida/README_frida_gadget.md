# Frida Gadget se TopFollow ko live instrument karna (non-rooted phone)

Yeh guide `REPORT_libtopfollow_so.md` ka companion hai. Report mein **static + emulated**
sab kuch prove kiya gaya hai; yahan wohi cheezein **asli phone par live** capture karni hain —
requests ka plaintext, AES keys, encrypted payloads, responses, aur detection functions ke hits.

Root ki zaroorat **nahi** hai. Tarika: APK ko repackage karke usme **Frida Gadget** daal dena.

> ⚠️ Yeh sirf education / security research ke liye hai. `com.nivaroid.topfollow` ek Instagram
> follower-exchange panel client hai; iske backend ke saath chhedchaad uski ToS aur kai
> jurisdictions mein kanoon todo sakti hai. Repackaged APK sirf **apne** device par,
> **apne** account ke saath chalayiye.

---

## 0. Ek nazar mein poora flow

```
 1. frida-gadget-<VER>-android-arm64.so.xz   download  -> libgadget.so
 2. apktool d TopFollow_v845-Beta.apk        (DEX -> smali)
 3. MyApp.smali ke <clinit>() mein System.loadLibrary("gadget") add karo   (§3)
 4. libgadget.so + libgadget.config.so  ->  smali/../lib/arm64-v8a/          (§4)
 5. apktool b                                (rebuild)
 6. zipalign -p 4  ...                       (extractNativeLibs=false ke liye ZAROORI) (§5)
 7. apksigner sign ...                       (§6)
 8. adb install -r
 9. app launch karo  ->  gadget ruk jaata hai  ->  PC se:
      python3 frida/run_frida.py --mode crypto                               (§7)
10. REPL mein:  selftest   selfcalibrate   crypto   keys   jni   detect      (§8)
```

Agar aapke paas Java/apktool/zipalign/apksigner **nahi** hain to §4–§6 ke liye is repo ke
pure-Python tools use kar sakte hain (`frida/repack_apk.py`), sirf §3 ka DEX patch aapko
kisi bhi DEX editor se karna padega — details §4B mein.

---

## 1. Zaroori cheezein

| Cheez | Version / note |
|---|---|
| PC | Windows / macOS / Linux |
| Java JDK | 17+ (`apksigner`, `zipalign`, `apktool` ke liye) |
| Android SDK **Build-Tools** | `zipalign` aur `apksigner` yahin milte hain (`$ANDROID_HOME/build-tools/34.0.0/`) |
| `apktool` | 2.9+ — https://apktool.org/ (script + `apktool.jar`) |
| `adb` | platform-tools |
| `frida` (Python) | **17.18.0** is repo mein test hua — `pip install frida` |
| Frida **Gadget** `.so` | **wahi version jo frida-python ka hai** (17.18.0) |
| Phone | arm64-v8a, Android 7.0+ (APK ka `minSdk 24`, `targetSdk 35`) |
| USB debugging | ON, aur phone PC par authorized |

Version match **sakht** hai: Gadget 16.x aur frida-python 17.x aapas mein baat nahi karenge
(`unable to communicate with remote frida-server: protocol version mismatch`).

```bash
python3 -c "import frida; print(frida.__version__)"     # jo yahan aaye, wahi gadget lijiye
pip install frida-tools                                  # `frida`, `frida-ps` CLI ke liye
```

---

## 2. Frida Gadget download karna

Release asset ka naam-yojna:

```
https://github.com/frida/frida/releases/download/<VER>/frida-gadget-<VER>-android-<ABI>.so.xz
```

Is APK ke liye:

```bash
VER=17.18.0
curl -L -o gadget.so.xz \
  "https://github.com/frida/frida/releases/download/${VER}/frida-gadget-${VER}-android-arm64.so.xz"
xz -d gadget.so.xz
mv gadget.so  frida/gadget/libgadget.so        # naam "libgadget.so" hi rakhna hai
ls -l frida/gadget/libgadget.so                # ~40 MB hona chahiye
```

> **Note (is sandbox se):** GitHub ka release CDN yahan se block tha — `302` ke baad TLS fail,
> `0 bytes`. Isliye `frida/gadget/` khali hai aur `.gitignore`d hai. Apne PC se download
> kijiye; browser se bhi ho jaata hai.

Doosre ABI (`lib/x86/`, `lib/x86_64/`) bhi APK mein hain. Gadget **sirf `arm64-v8a`** mein
daaliye — phone wahi load karega. Agar aap emulator (x86_64) par chala rahe hain to us ABI ke
liye alag gadget aur alag repack banaiye.

Naam `libgadget.so` kyun? Kyunki Android ka native loader `lib*.so` pattern maanta hai, aur
Gadget apna config file **apne hi naam se** dhoondhta hai: `libgadget.so` →
`libgadget.config.so`, usi directory mein.

---

## 3. DEX patch — Gadget ko load karwana  ★ sabse zaroori step

Gadget khud load nahi hota; kisi ko `System.loadLibrary("gadget")` bolna padta hai.

### 3.1 Sahi jagah: `MyApp.<clinit>()`

`AndroidManifest.xml` mein `android:name="com.nivaroid.topfollow.application.MyApp"` hai, aur
us class ka static initializer **already** `libtopfollow.so` load karta hai. Decompiled
(`classes.dex`, byte-verified):

```java
// com.nivaroid.topfollow.application.MyApp
static {                                    // <clinit>()V — regs=1, ins=0, 3 code units
    System.loadLibrary("topfollow");
}
public void onCreate() {                    // regs=2, ins=1, 5 code units
    super.onCreate();
    G.getInstance().a = this;               // <- yahi Context singleton hai jise
}                                           //    func#73/func#226 signature check ke liye use karte hain
```

Yeh **best** injection point hai, do wajah se:

1. `<clinit>` class load hote hi chalta hai — `onCreate()` se bhi pehle.
2. `loadLibrary("topfollow")` se **pehle** gadget load ho jaaye, to gadget ka
   `JNI_OnLoad`-time kaam aur uske andar ke saare checks humare hooks ke *baad* aate hain.
   Report §7.13: `func#57`/`func#67` `func#99` (anti-Frida), `func#200` (anti-hook),
   `func#225` (maps integrity) chalate hain — sab kuch baad mein hota hai, isliye order zaroori hai.

### 3.2 apktool se

```bash
apktool d -f -o tf TopFollow_v845-Beta.apk
```

`tf/smali/com/nivaroid/topfollow/application/MyApp.smali` kholiye. (Is APK mein ek hi
`classes.dex` hai, isliye `smali/` hi hoga — `smali_classes2/` nahi. Phir bhi
`grep -rl 'MyApp;' tf/smali*` se confirm kar lijiye.)

**Pehle (asli):**

```smali
.method static constructor <clinit>()V
    .registers 1

    .line 1
    const-string v0, "topfollow"

    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    return-void
.end method
```

**Baad mein (patched):**

```smali
.method static constructor <clinit>()V
    .registers 2

    .line 1
    const-string v0, "gadget"

    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    const-string v0, "topfollow"

    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    return-void
.end method
```

Badlaav sirf do hain:

| Kya | Pehle | Baad | Kyun |
|---|---|---|---|
| `.registers` | `1` | **`2`** | ek hi instruction mein 2 code units chahiye; register count badhana padta hai warna verifier reject karega |
| naya `const-string` + `invoke-static` | — | **`"gadget"`** wala pair, `topfollow` se **pehle** | gadget pehle load ho |

`"gadget"` string literal apktool/smali khud DEX string pool mein daal dega aur string-ids ko
dobara sort karega — yahi wajah hai ki yeh step **apktool se karna chahiye**, haath se DEX
bytes edit karke nahi.

> `libgadget.so` na milne par `System.loadLibrary` `UnsatisfiedLinkError` phenkta hai aur app
> crash ho jaata hai. Isliye §4 mein file sahi jagah + sahi naam se daalna mat bhooliye.
> Crash se bachne ke liye defensive variant (agar aap chahein):
> ```smali
>     const-string v0, "gadget"
>     invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
> ```
> ko `:try_start_0 … :try_end_0 .catch Ljava/lang/UnsatisfiedLinkError; {:try_start_0 .. :try_end_0} :catch_0`
> mein lapet lijiye. Par phir gadget chup-chaap load na hone par aapko pata nahi chalega —
> research build mein bina `try` ke rakhna behtar hai.

### 3.3 Verify karna

```bash
grep -A14 '<clinit>' tf/smali/com/nivaroid/topfollow/application/MyApp.smali
```

`.registers 2` aur `"gadget"` dono dikhne chahiye.

`frida/repack_apk.py` bhi yeh check karta hai (DEX mein `"gadget"` string dhoondh kar) aur
status print karta hai.

---

## 4. Gadget + config APK mein daalna

### 4A. apktool wala rasta (§3 ke saath)

Do files `tf/lib/arm64-v8a/` mein rakhiye:

```bash
mkdir -p tf/lib/arm64-v8a
cp frida/gadget/libgadget.so          tf/lib/arm64-v8a/libgadget.so
cp frida/libgadget.config.so          tf/lib/arm64-v8a/libgadget.config.so
ls -l tf/lib/arm64-v8a/
#   libdatastore_shared_counter.so
#   libgadget.config.so          <-- 155 B
#   libgadget.so                 <-- ~40 MB
#   libtopfollow.so              <-- 1,805,400 B (asli, UNCHANGED)
```

`libtopfollow.so` ko **chhediye mat**. Report ke saare offsets (`func#85 @0x10c470` wagairah)
isi file ke against hain; ek byte bhi badla to agent ke anchors fail honge aur
`rpc.exports.selfCalibrate()` 22/22 nahi dega.

Config file teen variant hain, is repo mein:

| File | Behaviour | Kab use karein |
|---|---|---|
| **`frida/libgadget.config.so`** | `listen 127.0.0.1:27042`, **`on_load: wait`** | ★ default. App `loadLibrary("gadget")` par **ruk jaati hai** jab tak aap attach na karein. Isse `JNI_OnLoad` ke pehle hook lag jaate hain — ek bhi call miss nahi hota. |
| `frida/libgadget.config.resume.so` | same, `on_load: resume` | App turant chal padti hai; aap baad mein attach karein. Late-attach hone par `JNI_OnLoad` ke andar ke detection calls miss ho sakte hain. |
| `frida/libgadget.config.script.so` | `type: script`, `path: /data/local/tmp/topfollow_agent.js` | PC attach nahi karna; agent APK ke andar hi chale. Pehle `adb push frida/topfollow_agent.js /data/local/tmp/` karna padega. `rpc.exports` REPL nahi milega (logs `adb logcat` mein aayenge). |

`wait` ka matlab: app ki UI thread block rehti hai (screen blank/ANR jaisi lag sakti hai) jab
tak aap `run_frida.py` na chalaayein. Yeh normal hai.

### 4B. Bina Java/apktool ke — `frida/repack_apk.py`

Is repo ka tool ZIP surgery karta hai: saare 1,266 entries **raw** copy (koi re-compression
nahi), gadget + config STORED aur **4096-byte aligned**, purane signature artifacts hata kar
fresh central directory. Verified: 0 payload change, 0 compression-method change, saari 8
`.so` entries `%4096 == 0`, `zipfile.testzip()` clean, androguard parse kar leta hai.

```bash
python3 frida/repack_apk.py \
    --apk     TopFollow_v845-Beta.apk \
    --gadget  frida/gadget/libgadget.so \
    --config  frida/libgadget.config.so \
    --out     tf-unsigned.apk
```

Par **DEX patch (§3) yeh tool nahi karta** — uske liye DEX string pool rebuild chahiye, jo
bina java ke karna safe nahi. Tool check karke bata deta hai ki patch hui hai ya nahi:

```
  classes.dex  string "gadget" NAHI hai
  --> DEX patch ka status upar dekh lijiye.
```

To is raste ka sequence: pehle kisi DEX editor se patch kijiye (apktool, ya
[MT Manager](https://bin-mt.com.cn/) / APK Editor Studio jaisa Android-side tool), phir
`repack_apk.py --apk <patched>.apk` chalaiye.

Android 15+ ke 16 KB-page devices par `--align 16384` dijiye.

---

## 5. Align karna (`zipalign`) — is APK mein ** compulsory**

`AndroidManifest.xml` mein `android:extractNativeLibs="false"` hai (androguard se verified).
Matlab: Android `.so` ko `/data` mein copy **nahi** karta, seedhe APK ke andar se `mmap`
karta hai. Iske liye har uncompressed `.so` ka data page-aligned hona chahiye, warna install
ke baad:

```
dlopen failed: library "libgadget.so" not found
```

ya

```
INSTALL_FAILED_INVALID_APK
```

**apktool se rebuild kiya hai to alignment zaroor kijiye** (apktool `-c`/`--use-aapt2` se bhi
alignment bigad jaati hai):

```bash
zipalign -p -f -v 4 tf-unsigned.apk tf-aligned.apk
zipalign -c -p -v 4 tf-aligned.apk           # verify: har .so par "OK" aana chahiye
```

`-p` = page-align uncompressed `.so` files. `4` = 4 KB. **Align sign karne se PEHLE karte
hain**, kyunki `apksigner` alignment ko chheda nahi (v2 block central directory ke pehle
jaata hai, entries ko hilata nahi).

`frida/repack_apk.py` alignment khud kar deta hai, to uske output par `zipalign -c` sirf
**verify** ke liye chalayiye (dobara align karne ki zaroorat nahi).

---

## 6. Sign karna

Original APK **v2-only** signed hai (v1 `META-INF/*.RSA` hai hi nahi, v3 nahi). `targetSdk 35`
matlab Android 11+ par v2/v3 ** compulsory** hai — sirf v1 se sign kiya APK install hi nahi
hoga.

### 6.1 Keystore banaiye

Koi bhi naya key chal jaayega:

```bash
keytool -genkeypair -v \
  -keystore frida/keys/debug.p12 -storetype PKCS12 \
  -storepass topfollow -keypass topfollow \
  -alias topfollow -keyalg RSA -keysize 2048 -validity 10000 \
  -dname "CN=TopFollow Research, OU=RE, O=RE, L=X, ST=X, C=IN"
```

### 6.2 (Optional) `clone_signer.py` — signature pin ke liye

```bash
python3 frida/clone_signer.py
```

Yeh report §6.5B ko prove karta hai aur ek structurally-identical certificate banata hai
(same subject/issuer DN `CN=Maryam Ahmadi, OU=Android Developer, O=NivaRoid, L=Shiraz,
ST=Fars, C=IR`, serial `1`, validity `2023-12-15T17:44:33Z .. 2048-12-08T17:44:33Z`,
sha256WithRSA, sirf public key naya) → `frida/keys/topfollow_clone.p12`
(alias `topfollow`, password `topfollow`).

**Honest limitation:** isse native signature check pass **nahi** hoga. Android 7+ par
`PackageManager` signature **v2/v3 Signing Block** se deta hai, aur original private key
humare paas nahi hai — isliye wahan humara clone cert hi jaayega aur uska SHA-256 pinned
value se match nahi karega. Check ko pass karane wala asli kaam agent ka Java-side forgery
hook karta hai (§7.4 / report §6.5C). `clone_signer.py` ka fayda yeh hai ki v1 scheme bhi
sahi shape ka cert carry karti hai, aur — zyada important — yeh **pin ki pehchaan byte-exact
prove** karta hai.

### 6.3 Sign

```bash
apksigner sign \
  --ks frida/keys/debug.p12 --ks-type PKCS12 \
  --ks-pass pass:topfollow --key-pass pass:topfollow --ks-key-alias topfollow \
  --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \
  --out TopFollow_v845-gadget.apk \
  tf-aligned.apk

apksigner verify -v --print-certs TopFollow_v845-gadget.apk
zipalign -c -p -v 4 TopFollow_v845-gadget.apk | tail -3     # abhi bhi aligned hona chahiye
```

---

## 7. Install + attach

```bash
# purana (asli) app pehle hata dijiye — signature badal gayi hai, upgrade install fail hoga
adb uninstall com.nivaroid.topfollow
adb install -r TopFollow_v845-gadget.apk

# Gadget port ko PC se reachable banaiye (usb par zaroori nahi, par remote mode mein chahiye)
adb forward tcp:27042 tcp:27042
```

Ab **phone par app launch kijiye**. `on_load: wait` hai to app gadget init par ruk jaayegi
(screen blank lag sakti hai) — yeh expected hai.

PC par:

```bash
frida-ps -U | head                     # 'Gadget' dikhna chahiye
python3 frida/run_frida.py --mode crypto
```

Ya seedha frida CLI se:

```bash
frida -U Gadget -l frida/topfollow_agent.js
```

Runner ke options:

```
--mode recon|crypto|bypass|all   kitna aggressive ho (default: crypto)
--name Gadget                    process naam (default: Gadget)
--device usb|remote|local        default usb; remote ke liye --host 127.0.0.1:27042
--package com.nivaroid.topfollow --spawn   (rooted / frida-server ke liye)
--timeout 120                    process ka wait
--save capture.json              saare records JSON mein
--rpc selftest                   ek RPC call karke exit
--offline-decrypt <hex>          bina phone ke ciphertext decrypt
```

### 7.1 Modes

| Mode | Kya karta hai | Kab |
|---|---|---|
| `recon` | sirf **dekhta** hai: crypto hooks + detection logging, par SSL unpinning OFF, signature forgery OFF, koi `replace` nahi | pehla run. App normal chalti hai, aap dekh rahe hain ki detection kab fire hoti hai |
| `crypto` (default) | `recon` + SSL unpin + signature forgery + `/proc/self/maps` filtering | ★ asli kaam. Requests/responses ka plaintext + keys |
| `bypass` | `crypto` + `stubDetection` (agar aap `--set stubDetection=true` dein) | detection actually block karni ho |
| `all` | sab kuch | — |

> **`stubDetection` default `false` hai, `bypass` mode mein bhi.** Wajah: `func#200/#99/#162/
> #225/#169` ka return polarity **prove nahi hua**. `0` force kar dena galat ho sakta hai —
> "0 = detected" bhi ho sakta hai, jisse app ko pata chal jaaye ki kuch gadbad hai. Pehle
> `recon`/`crypto` mein **natural return value** dekhiye (`detect()` mein `ret` field aata
> hai), polarity samajh aaye, tab hi `--set stubDetection=true --set forceReturn='{"0x145f88":1}'`
> jaisa override dijiye.
> `func#224 @0x157628` ko isliye chhoda gaya hai kyunki uske body mein `0x1576ac` par ek
> **reachable `b .` trap** hai (report §3.8).

---

## 8. REPL — kya kya nikaal sakte hain

Attach hone ke sabse pehle **do** command chalayiye:

```
tf> selftest
  allOk=True passed=26 failed=0 skipped=0
tf> calibrate
  ok=True matched=22/22
```

* `selftest` — agent ke andar ka JS AES/SHA-256 aur **live memory** se padhe gaye
  `.rodata` secrets ko report §11 ke 26 known-answer vectors se milata hai. Fail matlab
  kuch fundamental galat hai.
* `calibrate` — live `JNINativeMethod` table (`base + 0x1b6198`, 22 entries, stride `0x18`)
  ko static recovery se milata hai. **22/22** matlab report ke saare offsets is build par
  sahi hain. Kam matlab alag build/ABI — wahin ruk jaaiye.

Uske baad:

| Command | Kya milta hai |
|---|---|
| `secrets` | `func#193` ke through XOR-`0x5A` se decode hue **saare** strings, live |
| `keys` | `func#14` (LibTomCrypt `rijndael_setup`) ko diye gaye **saare AES keys**, key length ke saath |
| `crypto` | `func#85`/`#94`/`#30`/`#36` ke har call ka **plaintext + key + ciphertext**. Yahi request/response payload hai |
| `jni` | 22 natives ke saare Java-side calls, arguments ke saath (`q.a`…`q.v` + `x00…` slugs) |
| `detect` | detection hits: maps-reader entry, filtered read() buffers, anti-Frida, root, timing, aur signature forgery ke events |
| `signature` | report §6.5 ka poora hisaab, live: pinned SHA-256, `0x15084` se padha gaya blob, uska double-Base64 decode, `liveMatchesPin`, aur original cert ke 864 bytes |
| `knownkeys` | 9 hardcoded key material entries (Base64 + raw hex) |
| `vectors` | §11 ke vectors abhi dobara compute karke |
| `notes` | agent ke warnings/notes (jaise `func#30` ka >220-byte divergence warning) |
| `decrypt <hex>` | capture kiya hua ciphertext offline decrypt — pehle `func#30` zero-key CBC, phir har known key ke saath ECB aur CBC. 16/24/32-byte keys verbatim; 12-byte getter keys zero-pad/repeat/base64-text ke roop mein **`GUESS`** flag ke saath |
| `decrypt <hex> <key>` | ek specific ASCII key ke saath |
| `xordecode <off> <len> [key]` | live `.rodata` blob ko XOR-decode (default key `0x5a`) |
| `read <off> <len>` | live module se raw hex |
| `raw <expr>` | koi bhi export seedha, e.g. `raw crypto()` |
| `dump` | upar ke saare lists ek saath JSON |
| `clear` | buffers khaali |

Sab kuch JSON mein chahiye to:

```bash
python3 frida/run_frida.py --mode crypto --save capture.json
```

### 8.1 Request / response capture — practical recipe

Report §2.2A se pata hai kaunsa native kya karta hai. Uske hisaab se:

| Aapko chahiye | Hook / command |
|---|---|
| **Request body ka plaintext** | `func#57` (slot 6, `q.v(JsonObject)`) sabse bada builder hai — `crypto` mein uske `func#85`/`func#30` calls aayenge. `jni` mein `q.v` ka `JsonObject` argument bhi dikhega |
| **Response body ka plaintext** | `func#67` (slot 16, `q.p(Response,Order,InstagramAccount)`) — `inflate()` ke baad `func#30` se decrypt hota hai |
| **Live AES key** | `keys` — `func#14` har key install par hit hota hai (uske 4 callers: `func#30`, `#36`, `#85`, `#94`) |
| **GCM key/nonce install** | `func#157`/`func#158` hooks; dono sirf slot 6 (`q.v`) se reach hote hain, `func#157` slot 13 (`q.b`) se bhi |
| **Hardcoded key material** | `knownkeys` — 4 getters (`#86`→`5VEJK9Uk4d0elpVT`, `#159`, `#160`, `#161`) + AES-192 key `02df7523…` + 2 GCM nonces |
| **TLS pin ka asli value** | `detect`/`notes` mein `CertificatePinner.Builder.add` ke arguments — report §10 item 30 ke mutabik yeh value `.so` mein static **nahi** hai, sirf live capture se milegi |
| **Signature check kab chalta hai** | `detect` — `getPackageInfo … FORGED` entries, aur `func#73`/`func#226` ke watch hits |

Ek typical session:

```
tf> selftest          # 26/26
tf> calibrate         # 22/22
tf> keys              # khali hoga — abhi koi crypto nahi hua
# phone par app mein login kijiye, koi order place kijiye
tf> crypto            # ab plaintext + key + ciphertext aayega
tf> jni               # kaunse natives call hue, kis order mein
tf> detect            # detection ne kya dekha, humne kya chhupaya
tf> dump              # sab kuch
```

---

## 9. Kya chhupaya ja raha hai, aur kyun

### 9.1 `/proc/self/maps` filtering (read-only, libc-side)

Detection functions:

| Function | Address | Kya dekhta hai |
|---|---|---|
| `func#99` | `0x115770` | XOR-`0x37` blob ke tokens (`gum-js-loop`, `libfrida-gadget`, `re.frida.server`) |
| `func#162` | `0x136cb8` | wahi tokens, **plain Base64** C strings mein chhupe hue |
| `func#200` | `0x145f88` | anti-hook scan, XOR-`0x5A` blob (`U`…`Z` guards ke beech 9 tokens) |
| `func#225` | `0x157f38` | `rwxp`, `libart.so (deleted)`, `libc.so (deleted)` |
| `func#60` | `0x081c58` | **179,828 B** ka scanner: `xposed`, `edxposed`, `lsposed`, `substrate`, `libcso_substrate`, `riru`, `libbridge.so`, `ygsik` |
| `func#169` | `0x13ba30` | 9 su paths par `access()` |

**Sabse zaroori baat (revision 4 mein pata chali):** `libtopfollow.so` ki poori import table mein
sirf **88 symbols** hain, aur unmein **`fopen` nahi, `fgets` nahi, `strstr` nahi, `stat` nahi,
`lstat` nahi**. File padhne ke liye sirf yeh hain: `__open_2` (8 call sites), `__read_chk` (6),
`read` (3), `close` (6), `access` (1).

Iska matlab yeh hai ki maps scanners `fopen`+`fgets` use **nahi** karte. Teen reader helpers hain
jo `open()`+`read()` se poora file ek buffer mein padhte hain, aur phir har scanner apna khud ka
**inlined byte loop** chalata hai:

```
func#99 , func#225              ─> func#129 @0x11deb0 ─┐
func#162, func#200              ─> func#198 @0x143694 ─┼─> __open_2 + __read_chk/read + close
func#60                         ─> func#213 @0x151e68 ─┘
```

Isliye agent ab **`read()` ke buffer ko filter karta hai**, `fgets` ko nahi:

1. `__open_2` / `open` / `open64` / `openat` hook — jo fd `/proc/...maps` (ya `smaps`, `task/`)
   par khulta hai use ek set mein note kar leta hai.
2. `read` / `__read_chk` / `pread` / `pread64` hook — us fd se padhe gaye buffer ko `\n` par
   tod kar har suspicious line ko **exactly utni hi length** wali innocuous line se replace kar
   deta hai (`7f000000-7f001000 r--p 00000000 00:00 0` + spaces).
   **Length preserve karna hi safety hai**: `read()` ka return value sahi rehta hai, koi counter,
   koi register, koi function body touch nahi hoti, aur scanner ka apna line-splitter ko ek
   well-formed file hi milti hai.
3. `close` par fd tracking hat jaati hai.
4. `func#129` / `func#198` / `func#213` / `func#60` par **entry-only watch** (sirf log).

Token list 30 entries ki hai aur report §10 item 40 ki table se aayi hai. `fgets` aur `strstr`
hooks bhi code mein hain, par **defence in depth** ke taur par — is build mein woh kabhi fire
nahi honge. `strstr` suppression ko exact-match (length ≥ 6) par rakha gaya hai: `libc.so` aur
`libart.so` ek normal maps file ki aadhi lines mein legitimately aate hain, unhe substring-match
se dabana file ko shred kar deta — jo khud ek zyada bada detection signal hai.

Baaki:

* `access()` — 9 su paths par `ENOENT` (`stat`/`lstat` hooks bhi hain par library unhe import
  hi nahi karti, isliye woh sirf doosre builds ke liye hain).
* `clock()` — `func#98` ke andar se call hone par **sirf log**, fake nahi. Polarity prove nahin
  hui; galat guess app ko bata deta hai ki analysis ho rahi hai.

Yeh sab isliye zaroori hai kyunki library **control-flow flattened** hai aur usme **712 `b .`
infinite-loop instructions** hain, **148 reachable** (report §3.8). Yeh opaque predicates ke
else-arm hain: agar hook kisi register ko chhed de jise predicate padhta hai, control flow
`b .` par ja girta hai aur thread **chup-chaap hang** ho jaata hai — koi crash nahi, koi error
nahi. Isliye hard rule:

> **Flattened functions par sirf entry-only `Interceptor.attach`, aur sirf registers PADHNA.
> Kabhi `Interceptor.replace` nahi. Kabhi function body ke andar patch nahi.**

### 9.1A Verify kijiye ki token list drift na ho

```bash
node frida/test_agent_offline.js        # 138 / 138 PASS
```

Test §10 **asli `libtopfollow.so` ke bytes se** har Base64 C string ko khud decode karta hai aur
assert karta hai ki 16 detection tokens waqai binary mein maujood hain *aur* `MAPS_NOISE` mein
covered hain. Test §11 ek synthetic 8-line maps chunk par `filterMapsBuffer` chala kar assert
karta hai: ≥5 lines rewritten, **total length unchanged**, **line count unchanged**, saatوں tokens
gayab, dono innocent lines byte-identical, aur bina `\n` wala partial chunk untouched.

### 9.2 Gadget khud ek detection surface hai

Gadget embed karne se maps mein yeh artifacts aate hain: `libgadget.so`, `frida-agent`,
`gum-js-loop` thread, `gmain`, `pool-frida`, aur `27042` par listening socket. Upar wala
`fgets` filter inhe chhupa deta hai. Naam badalna ho to gadget ko `libgadget.so` ki jagah
koi aur naam dijiye (config file ka naam usi ke hisaab se `lib<name>.config.so` hona chahiye)
aur smali patch mein wahi naam daaliye.

`on_load: wait` mode mein gadget khud `listen` socket kholta hai — `func#99` port scan nahi
karta (report §8 item 10: "No port 27042 probe"), isliye yeh theek hai.

---

## 10. Troubleshooting

| Symptom | Wajah / ilaaj |
|---|---|
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` / `signatures do not match` | Original app abhi installed hai. `adb uninstall com.nivaroid.topfollow` karke dobara install kijiye |
| `INSTALL_FAILED_INVALID_APK` | `.so` aligned nahi. `zipalign -c -p -v 4 <apk>` chalayiye; fail ho to `zipalign -p -f 4` se dobara align karke dobara sign kijiye |
| App turant crash, logcat mein `dlopen failed: library "libgadget.so" not found` | Gadget APK mein nahi hai, ya galat ABI folder mein hai, ya align nahi hai. `unzip -l <apk> \| grep gadget` se confirm kijiye |
| `java.lang.UnsatisfiedLinkError: dlopen failed: … libgadget.so` **aur** app chalta hai | Aapne `try/catch` variant use kiya — gadget load nahi hua, upar wala row dekhiye |
| `unable to connect to remote frida-server: protocol version mismatch` | Gadget aur `frida`-python ke version alag hain. Dono 17.18.0 kijiye |
| `process 'Gadget' not found` | App launch nahi kiya, ya config `on_load: resume` hai aur app already aage nikal gayi. `frida-ps -U \| grep -i gadget`; `--timeout 180` badhaiye; app ko force-stop karke dobara launch kijiye |
| App `wait` par atki hai, screen blank | Normal. PC par `run_frida.py` chalayiye; attach hote hi aage badhegi |
| Agent boot hota hai par `MODULE` line nahi aati | `libtopfollow.so` abhi load nahi hua. Agent `dlopen`/`android_dlopen_ext` hook + polling se wait karta hai — app mein kuch kijiye jisse native code chale (login) |
| `selftest` fail | Agent ka JS AES ya offsets galat. `--mode recon` mein chalayiye aur `notes` dekhiye |
| `calibrate` < 22/22 | Yeh **doosri build** hai. Report ke offsets is par valid nahi. `calibrate` ka output live offsets deta hai — usi se aage badhiye |
| App "network error" / requests fail | `func#226` signature check fail ho raha hai aur crypto path poison ho gaya hai (report §6.5: "failure poisons the crypto path rather than throwing a clean error"). `spoofSignature` ON hai confirm kijiye (`config`), aur `detect` mein `FORGED` entries dekhna chahiye |
| TLS/burp mein traffic nahi dikh raha | SSL unpin chahiye: `--mode crypto` (default). Phir bhi na chale to `--set sslUnpin=true` confirm kijiye |
| Thread hang, koi crash nahi, CPU 100% | Kisi flattened function par `replace` laga hai ya register write ho raha hai. `stubDetection` OFF kijiye aur `--mode recon` par wapas aaiye (report §3.8, §8 item 7) |
| `func#30` ka ciphertext report se mismatch, plaintext >220 bytes | Expected — report §10 item 27: 221+ bytes par `func#30` CBC byte 208 se diverge karta hai. Agent is par warning bhi daalta hai |

---

## 11. Rooted phone ho to (zyada aasaan)

Gadget/repack ki zaroorat hi nahi:

```bash
adb push frida-server-17.18.0-android-arm64 /data/local/tmp/frida-server
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
adb shell "su -c '/data/local/tmp/frida-server &'"

python3 frida/run_frida.py --package com.nivaroid.topfollow --spawn --mode crypto
```

`--spawn` se app scratch se start hoti hai, to `JNI_OnLoad` se pehle hooks lag jaate hain.
Par root hone se `func#169` ka root check fire hoga — `detect` mein dekhiye, aur
`access()` ENOENT layer default ON hai.

Naam badla hua `frida-server` use kijiye: `func#99` naam-based detection karta hai
(`gum-js-loop`, `libfrida-gadget`, `re.frida.server`) — report §8 item 10.

---

## 12. Files in this directory

```
frida/
├── README_frida_gadget.md            yeh file
├── topfollow_agent.js                ★ the agent (1,989 lines, 17 rpc.exports)
├── test_agent_offline.js             node se 138 assertions (phone ki zaroorat nahi)
├── run_frida.py                      runner + REPL + --offline-decrypt
├── repack_apk.py                     pure-Python APK injector (ZIP + alignment)
├── clone_signer.py                   signature-pin proof + clone keystore generator
├── libgadget.config.so               listen 127.0.0.1:27042, on_load=wait   ★ default
├── libgadget.config.resume.so        listen …, on_load=resume
├── libgadget.config.script.so        script /data/local/tmp/topfollow_agent.js
├── gadget/                           yahan libgadget.so rakhiye (.gitignore'd)
└── keys/                             generated keystores + original_cert.der (.gitignore'd)
```

Bina phone ke verify kar lijiye ki sab kuch sahi hai:

```bash
node frida/test_agent_offline.js      # PASS 138 FAIL 0
python3 frida/clone_signer.py         # SHA-256(cert DER) == pinned digest
python3 frida/repack_apk.py --dry-run
python3 frida/run_frida.py --offline-decrypt \
  f49288051d7d9decc641ea07eb7ff32cbde7e2be9f3006617f3938a20f63549cfc144d3ce97d67ecc55475f0dfeec781
#   -> '{"order_id":12345,"type":"follower"}'
```

---

*Companion report: [`REPORT_libtopfollow_so.md`](../REPORT_libtopfollow_so.md) — §6.5 signature
pin, §2.2A JNI call-graph, §3.8 `b .` traps, §11 dynamic proof, §11.10 is harness ka
verification status.*
