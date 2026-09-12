# Reproducing the analysis

Start point is the committed `TopFollow_v845-Beta.apk`. Three large artifacts are
git-ignored (`work/apk_extracted/`, `work/analysis/annotated_arm64.txt`,
`work/analysis/full_disasm_arm64.txt`, `work/analysis/funcmap.json`); rebuild them
with the steps below. Everything the report cites that is *not* ignored is already
committed under `work/analysis/`.

## 1. Environment

```bash
cd /home/user/apk
python3 -m venv .venv
.venv/bin/pip install capstone==5.0.7 lief==1.0.0 androguard==4.1.4
```

(`pip install` without a venv fails: PEP 668 externally-managed. There is no root,
so no `openjdk` — `jadx`/`baksmali` are unavailable and the GitHub release CDN is
blocked from this sandbox. `androguard` covers the DEX side.)

## 2. Unpack

```bash
mkdir -p work/apk_extracted
unzip -o TopFollow_v845-Beta.apk -d work/apk_extracted
strings -a -n 4 work/apk_extracted/lib/arm64-v8a/libtopfollow.so \
  | cat -n > work/strings_dump.txt
```

Yields `lib/{arm64-v8a,x86,x86_64}/libtopfollow.so` and `classes.dex`.

## 3. ELF model (sections, imports, exports, function boundaries)

```bash
.venv/bin/python work/analysis/elf_model.py \
    work/apk_extracted/lib/arm64-v8a/libtopfollow.so \
    work/analysis/model_arm64.json
.venv/bin/python work/analysis/elf_model.py \
    work/apk_extracted/lib/x86_64/libtopfollow.so \
    work/analysis/model_x64.json
```

Function discovery uses `.eh_frame` FDEs (the binary is stripped), which is why the
recovered count is 1,090 and not whatever a heuristic sweep guesses.

## 4. Disassembly + cross-references

```bash
.venv/bin/python work/analysis/disasm.py     # -> work/analysis/full_disasm_arm64.txt
.venv/bin/python work/analysis/xref.py       # -> xrefs.json, calls.json, plt_map.json,
                                             #    annotated_arm64.txt
```

`xref.py` resolves every `adrp`+`add`/`ldr` pair to an absolute `.rodata`/
`.data.rel.ro` target and every `bl` to its PLT name. **That resolution step is what
makes the detection-function attribution in §6 of the report possible** — do not skip
it, string proximity alone gives wrong answers (see report §10, corrections 2 and 3).

## 5. Per-function profiles

```bash
.venv/bin/python work/analysis/funcmap.py    # -> funcmap.json
```

> ⚠ The mnemonic parser must use
> `^0x([0-9a-f]+):\s+([0-9a-f]+)\s+(\S+)\s*(.*)$`.
> An earlier version split on whitespace and captured the instruction *encoding*
> instead of the mnemonic, silently zeroing every counter. `obf_report.txt` as
> committed is from the fixed version.

## 6. String decryption

```bash
.venv/bin/python work/analysis/decrypt_strings.py   # -> xor_strings.txt
.venv/bin/python work/analysis/decode_refs.py       # -> decoded_refs.txt
```

`decrypt_strings.py` sweeps all 256 single-byte XOR keys over all 1,585 `.rodata`
units. `decode_refs.py` additionally unwraps nested Base64 up to 5 layers.

Two gotchas that cost time and are worth knowing up front:

* The packed XOR blobs have **no delimiter byte**. Do not tokenise on `\x00`/`\x1a` —
  recover token boundaries from the *data refs* of the owning function instead
  (`func#200` has 9 refs into `0x1746f..0x174c4`, one per token; `func#99` has 3 into
  `0x17365..0x1738e`). Offsets between consecutive refs give the lengths.
* Blob start offsets are off-by-one-prone. The Frida blob starts at **`0x17365`**, not
  `0x17366`; starting a byte late silently drops the leading `g` of `gum-js-loop`.
  The hook blob is framed by literal `U`(0x55)/`Z`(0x5A) guard bytes at `0x1746f`/`0x174c3`.

## 7. Detection / crypto attribution (the authoritative table)

The inversion in `work/analysis/final_detection_map.txt` is produced by walking
`funcmap.json` and, for each interesting `.rodata` range, listing every function with
a data ref inside it plus that function's callers. Ranges used are listed inline in
the script body — extend that dict to attribute new blobs.

## 8. DEX side

```bash
.venv/bin/python work/analysis/dex_scan.py     # APK metadata, permissions, classes
.venv/bin/python work/analysis/dex_jni.py      # all native method declarations
.venv/bin/python work/analysis/dex_layer.py    # helper/q, helper/T, helper/a0, application/G, db/MyDatabase
.venv/bin/python work/analysis/dex_models.py   # DeviceModel / InstagramAccount / Order fields
```

## 9. Quick verification of the headline findings

```bash
.venv/bin/python - <<'PY'
d=open('work/apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
import struct
print("AES key  @0x17428:", d[0x17428:0x17448].hex())          # 1b2e636b...141b
print("AES IV   @0x17448:", d[0x17448:0x17458].hex())          # 0d170c1f...3708
print("2nd key  @0x17307:", d[0x17307:0x17327].hex())          # 90fefac8...6b3f
print("LTC Rcon @0x135b0:", d[0x135b0:0x135b4].hex()=="5150a7f4")   # True => LibTomCrypt
print("LTC log  @0x13b10:", d[0x13b10:0x13b14].hex()=="01020408")   # True
print("SHA256 H0@0x17220:", [hex(struct.unpack_from('<I',d,0x17220+4*i)[0]) for i in range(8)][0]=="0x6a09e667")
print("SHA256 K @0x174c4:", hex(struct.unpack_from('<I',d,0x174c4)[0])=="0x428a2f98")
print("root XOR @0x173a7:", bytes(x^0x5a for x in d[0x173a7:0x173af]))   # b'/sbin/su'
print("frida XOR@0x17365:", bytes(x^0x37 for x in d[0x17365:0x1738e]))   # starts 0x17365 -> "gum-js-loop..."
print("hook  XOR@0x1746f:", bytes(x^0x5a for x in d[0x1746f:0x174c4]))   # U...Z guards, 9 packed tokens
PY
```
