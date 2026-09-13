#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
repack_apk.py — Frida Gadget ko TopFollow APK mein inject karna, bina Java ke
==============================================================================

Yeh tool ZIP surgery karta hai (apktool / zipalign / apksigner ki zaroorat
NAHI), aur `extractNativeLibs="false"` ke liye zaroori **4096-byte alignment**
khud maintain karta hai — jo cheez `zipalign -p 4` karta hai.

Kya karta hai
-------------
  1. Original APK ke har entry ko RAW (bina re-compress kiye) copy karta hai.
  2. `lib/arm64-v8a/libgadget.so`            STORED + 4096-aligned  add karta hai
  3. `lib/arm64-v8a/libgadget.config.so`     STORED + 4096-aligned  add karta hai
  4. (optional) `libgadget.script.so`        STORED + 4096-aligned  add karta hai
  5. Purane `META-INF/*.SF|.RSA|.DSA|.EC` hata deta hai (signature invalid ho
     chuki hoti hai) aur koi APK Signing Block nahi likhta.
  6. Central directory + EOCD fresh banata hai.

Kya NAHI karta hai
------------------
  * DEX patch. `System.loadLibrary("gadget")` call aapko smali mein daalni hai
    (exact patch README_frida_gadget.md §3 mein hai). Yeh tool check karta hai
    ki patch hui hai ya nahi, aur agar nahi hui to saaf-saaf bata deta hai.
  * Signing. Woh `apksigner` se karni hai (README §5) — Android 11+ par v2/v3
    zaroori hai, aur v2 signing block ZIP ke andar ek specific jagah jaata hai
    jise bina apksigner ke sahi likhna possible nahi.

Usage
-----
    python3 frida/repack_apk.py \
        --apk     TopFollow_v845-Beta.apk \
        --gadget  frida/gadget/libgadget.so \
        --config  frida/libgadget.config.so \
        --out     TopFollow_v845-gadget-unsigned.apk

    # script-type config (agent APK ke andar hi chale, PC ki zaroorat nahi):
    python3 frida/repack_apk.py --apk ... --gadget ... \
        --config frida/libgadget.config.script.so \
        --script frida/topfollow_agent.js

    # sirf check karna hai, kuch likhna nahi:
    python3 frida/repack_apk.py --apk ... --dry-run
"""
import argparse
import binascii
import hashlib
import os
import struct
import sys
import time
import zipfile

SO_ALIGN = 4096          # `zipalign -p 4` on 16 KB-page devices = 4096 is enough
                         # for Android <= 14; use --align 16384 for Android 15+
                         # 16 KB-page devices.

# ---------------------------------------------------------------- ZIP format --
LFH_SIG = 0x04034b50
CDH_SIG = 0x02014b50
EOCD_SIG = 0x06054b50
ZIP64_EOCD_SIG = 0x06064b50
ZIP64_LOC_SIG = 0x07064b50
APK_SIG_MAGIC = 0x3234206b63615053          # "APK Sig Block 42"

COMPRESSION_NAMES = {0: 'STORED', 8: 'DEFLATED'}


def log(m):
    print(m, flush=True)


def warn(m):
    print('  [!] ' + m, flush=True)


def fatal(m):
    sys.exit('FATAL: ' + m)


class Entry:
    """One ZIP entry, kept as RAW compressed bytes so we never recompress."""
    __slots__ = ('name', 'method', 'crc', 'csize', 'usize', 'mtime', 'mdate',
                 'data', 'flags', 'align', 'extra')

    def __init__(self, name, method, crc, csize, usize, mtime, mdate, data,
                 flags=0, align=0, extra=b''):
        self.name = name
        self.method = method
        self.crc = crc
        self.csize = csize
        self.usize = usize
        self.mtime = mtime
        self.mdate = mdate
        self.data = data
        self.flags = flags
        self.align = align
        self.extra = extra


def dos_time(t=None):
    t = t or time.localtime()
    dosdate = ((t.tm_year - 1980) << 9) | (t.tm_mon << 5) | t.tm_mday
    dostime = (t.tm_hour << 11) | (t.tm_min << 5) | (t.tm_sec // 2)
    return dostime, dosdate


def read_apk(path, align_=SO_ALIGN):
    """Return (entries, had_signing_block). Uses zipfile for parsing but keeps
       the raw compressed payload of every entry."""
    if not os.path.exists(path):
        fatal('APK nahi mila: ' + path)
    with open(path, 'rb') as f:
        blob = f.read()

    # does an APK Signing Block exist? (sits right before the central directory)
    zf = zipfile.ZipFile(path)
    cd_off = None
    # find EOCD
    i = blob.rfind(struct.pack('<I', EOCD_SIG))
    if i < 0:
        fatal('EOCD nahi mila — yeh ZIP/APK corrupt hai')
    eocd = blob[i:i + 22]
    if len(eocd) < 22:
        fatal('EOCD truncated')
    cd_size, cd_off = struct.unpack('<II', eocd[12:20])
    had_block = False
    if cd_off >= 24:
        window = blob[max(0, cd_off - 4096):cd_off]
        if window.rfind(struct.pack('<Q', APK_SIG_MAGIC)) >= 0:
            had_block = True
    log('  EOCD @0x%x  central dir @0x%x size %d  APK Signing Block: %s'
        % (i, cd_off, cd_size, 'PRESENT' if had_block else 'none'))

    entries = []
    for zi in zf.infolist():
        raw = None
        # zipfile does not expose raw compressed bytes directly; re-read from
        # the local header so the output is byte-identical to the input.
        lfh = zi.header_offset
        if blob[lfh:lfh + 4] != struct.pack('<I', LFH_SIG):
            fatal('bad local header for ' + zi.filename)
        (sig, ver, flags, method, mtime, mdate, crc, csize, usize,
         nlen, elen) = struct.unpack('<IHHHHHIIIHH', blob[lfh:lfh + 30])
        data_start = lfh + 30 + nlen + elen
        raw = blob[data_start:data_start + csize]
        if len(raw) != csize:
            fatal('truncated payload for ' + zi.filename)
        name = zi.filename
        align = 0
        if name.startswith('lib/') and name.endswith('.so') and method == 0:
            align = align_
        entries.append(Entry(name, method, crc, csize, usize, mtime, mdate, raw,
                             flags & ~0x08, align, b''))
    zf.close()
    return entries, had_block


def new_stored_entry(name, data, align=SO_ALIGN):
    dostime, dosdate = dos_time()
    return Entry(name, 0, binascii.crc32(data) & 0xffffffff, len(data), len(data),
                 dostime, dosdate, data, 0, align, b'')


def is_sig_file(name):
    if not name.startswith('META-INF/'):
        return False
    up = name.upper()
    return up.endswith(('.SF', '.RSA', '.DSA', '.EC')) or up.endswith('MANIFEST.MF')


def write_apk(entries, out_path):
    """Emit the ZIP: local headers (+ alignment padding) then CD then EOCD."""
    out = bytearray()
    cd = bytearray()

    for e in entries:
        name_b = e.name.encode('utf-8')
        offset = len(out)

        # alignment: pad inside the local-header extra field so that the FILE
        # DATA starts on a multiple of `align`. This is exactly what
        # `zipalign -p 4` does.
        extra = b''
        if e.align:
            hdr = 30 + len(name_b)
            need = (-(offset + hdr)) % e.align
            if need:
                # 0xd935 = "alignment" extra field id used by zipalign
                pad = need - 4
                if pad < 0:
                    pad += e.align
                    need = pad + 4
                extra = struct.pack('<HH', 0xd935, pad) + b'\x00' * pad
            assert (offset + 30 + len(name_b) + len(extra)) % e.align == 0, \
                'alignment failed for ' + e.name

        out += struct.pack('<IHHHHHIIIHH', LFH_SIG, 20, e.flags, e.method,
                           e.mtime, e.mdate, e.crc, e.csize, e.usize,
                           len(name_b), len(extra))
        out += name_b + extra + e.data

        cd += struct.pack('<IHHHHHHIIIHHHHHII', CDH_SIG, 20, 20, e.flags,
                          e.method, e.mtime, e.mdate, e.crc, e.csize, e.usize,
                          len(name_b), 0, 0, 0, 0, 0o644, offset)
        cd += name_b

    cd_off = len(out)
    out += cd
    out += struct.pack('<IHHHHIIH', EOCD_SIG, 0, 0, len(entries), len(entries),
                       len(cd), cd_off, 0)

    with open(out_path, 'wb') as f:
        f.write(out)
    return cd_off


def verify(out_path, expect_names, page_align):
    log('\n[verify] %s  (%d bytes)' % (out_path, os.path.getsize(out_path)))
    with open(out_path, 'rb') as f:
        blob = f.read()
    zf = zipfile.ZipFile(out_path)
    bad = zf.testzip()
    log('  zipfile.testzip()      : %s' % ('OK (sab entries CRC-valid)' if bad is None
                                           else 'CORRUPT: ' + str(bad)))
    names = set(zf.namelist())
    for n in expect_names:
        log('  %-42s : %s' % (n, 'PRESENT' if n in names else 'MISSING  <-- PROBLEM'))

    # alignment check
    ok = True
    for zi in zf.infolist():
        if zi.compress_type != 0:
            continue
        if not (zi.filename.startswith('lib/') and zi.filename.endswith('.so')):
            continue
        lfh = zi.header_offset
        (sig, ver, flags, method, mt, md, crc, cs, us, nlen, elen) = \
            struct.unpack('<IHHHHHIIIHH', blob[lfh:lfh + 30])
        data_off = lfh + 30 + nlen + elen
        mod = data_off % page_align
        status = 'aligned' if mod == 0 else 'MISALIGNED (%d)' % mod
        if mod:
            ok = False
        log('  %-46s data@0x%08x  %%%d=%d  %s'
            % (zi.filename, data_off, page_align, mod, status))
    zf.close()

    # no APK signing block must remain
    i = blob.rfind(struct.pack('<I', EOCD_SIG))
    cd_off = struct.unpack('<I', blob[i + 16:i + 20])[0]
    still = (cd_off >= 24 and
             struct.unpack('<Q', blob[cd_off - 16:cd_off - 8])[0] == APK_SIG_MAGIC)
    log('  APK Signing Block       : %s' % ('STILL PRESENT <-- apksigner ko problem'
                                           if still else 'removed (good)'))
    sigs = [n for n in names if is_sig_file(n)]
    log('  META-INF signature files: %s' % (sigs if sigs else 'none (good)'))
    log('  overall alignment       : %s' % ('OK' if ok else 'FAIL'))
    return ok


def check_dex_patch(apk_path, libname):
    """Look for evidence that System.loadLibrary("<libname>") was added."""
    hits = []
    try:
        zf = zipfile.ZipFile(apk_path)
        for n in zf.namelist():
            if n.endswith('.dex'):
                data = zf.read(n)
                if ('"%s"' % libname).encode() in data:
                    hits.append((n, 'string "%s" DEX mein hai' % libname))
                else:
                    hits.append((n, 'string "%s" NAHI hai' % libname))
        zf.close()
    except Exception as e:
        warn('DEX check fail: %s' % e)
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    ap.add_argument('--apk', default=os.path.join(root, 'TopFollow_v845-Beta.apk'))
    ap.add_argument('--gadget', default=os.path.join(here, 'gadget', 'libgadget.so'))
    ap.add_argument('--config', default=os.path.join(here, 'libgadget.config.so'))
    ap.add_argument('--script', default=None,
                    help='agent JS, sirf script-type config ke liye (libgadget.script.so ban jaata hai)')
    ap.add_argument('--abi', default='arm64-v8a')
    ap.add_argument('--libname', default='gadget',
                    help='System.loadLibrary() mein jo naam daala hai (default: gadget)')
    ap.add_argument('--out', default=None,
                    help='default: TopFollow_v845-gadget-unsigned.apk (repo root)')
    ap.add_argument('--align', type=int, default=SO_ALIGN,
                    help='native lib alignment; 16384 for Android 15+ 16KB-page devices')
    ap.add_argument('--dry-run', action='store_true')
    a = ap.parse_args()

    align = a.align

    log('=' * 78)
    log('repack_apk.py  —  Frida Gadget injector (pure Python, no java/apktool)')
    log('=' * 78)

    if not os.path.exists(a.apk):
        fatal('APK nahi mila: ' + a.apk)
    log('\n[1] INPUT  %s  (%d bytes)' % (a.apk, os.path.getsize(a.apk)))
    entries, had_block = read_apk(a.apk, align)
    log('  entries: %d' % len(entries))
    stored = sum(1 for e in entries if e.method == 0)
    log('  STORED: %d   DEFLATED: %d' % (stored, len(entries) - stored))
    libs = [e.name for e in entries if e.name.startswith('lib/')]
    log('  native libs: %s' % libs)

    log('\n[2] MANIFEST / DEX CHECKS')
    try:
        from androguard.core.apk import APK
        m = APK(a.apk)
        log('  package                : %s' % m.get_package())
        log('  minSdk / targetSdk     : %s / %s' % (m.get_min_sdk_version(), m.get_target_sdk_version()))
        log('  application android:name: %s' % m.get_attribute_value('application', 'name'))
        log('  extractNativeLibs      : %s   <-- "false" matlab .so STORED+aligned hona CHAHIYE'
            % m.get_attribute_value('application', 'extractNativeLibs'))
        log('  signed v1/v2/v3        : %s/%s/%s' % (m.is_signed_v1(), m.is_signed_v2(), m.is_signed_v3()))
    except Exception as e:
        warn('androguard se manifest nahi padh paaye: %s' % e)

    for n, msg in check_dex_patch(a.apk, a.libname):
        log('  %-12s %s' % (n, msg))
    log('  --> DEX patch ka status upar dekh lijiye. Gadget tabhi load hoga jab')
    log('      MyApp;<clinit>() mein System.loadLibrary("%s") add kiya gaya ho.' % a.libname)

    log('\n[3] GADGET FILES')
    if not a.dry_run:
        if not os.path.exists(a.gadget):
            fatal('gadget .so nahi mila: %s\n'
                  'Download: https://github.com/frida/frida/releases/download/<VER>/\n'
                  '          frida-gadget-<VER>-android-%s.so.xz\n'
                  'phir:  xz -d  aur  mv frida-gadget-*.so  %s'
                  % (a.gadget, a.abi, a.gadget))
    else:
        log('  [dry-run] gadget file check skip')
    if os.path.exists(a.gadget):
        log('  gadget : %s (%d bytes) sha256=%s' % (a.gadget, os.path.getsize(a.gadget),
            hashlib.sha256(open(a.gadget, 'rb').read()).hexdigest()[:16]))
    if os.path.exists(a.config):
        log('  config : %s (%d bytes)' % (a.config, os.path.getsize(a.config)))
        log('           %s' % open(a.config, 'rb').read().decode('utf-8', 'replace')
            .replace('\n', '\n           '))
    else:
        warn('config nahi mila: %s — gadget apni DEFAULT config use karega '
             '(listen 127.0.0.1:27042, on_load=wait)' % a.config)
    if a.script:
        if os.path.exists(a.script):
            log('  script : %s (%d bytes)' % (a.script, os.path.getsize(a.script)))
        else:
            fatal('script nahi mila: ' + a.script)

    # ---- build the new entry list ----
    prefix = 'lib/%s/' % a.abi
    out_entries = []
    dropped = []
    for e in entries:
        if is_sig_file(e.name):
            dropped.append(e.name)
            continue
        if e.name == prefix + 'lib%s.so' % a.libname:
            continue   # replaced below
        if e.name == prefix + 'lib%s.config.so' % a.libname:
            continue
        if e.name == prefix + 'lib%s.script.so' % a.libname:
            continue
        out_entries.append(e)
    if dropped:
        log('\n[4] dropped stale signature files: %s' % dropped)

    if not a.dry_run:
        with open(a.gadget, 'rb') as f:
            out_entries.append(new_stored_entry(prefix + 'lib%s.so' % a.libname, f.read(), align))
        if os.path.exists(a.config):
            with open(a.config, 'rb') as f:
                out_entries.append(new_stored_entry(prefix + 'lib%s.config.so' % a.libname,
                                                    f.read(), align))
        if a.script:
            with open(a.script, 'rb') as f:
                out_entries.append(new_stored_entry(prefix + 'lib%s.script.so' % a.libname,
                                                    f.read(), align))
        out_path = a.out or os.path.join(root, 'TopFollow_v845-gadget-unsigned.apk')
        log('\n[5] WRITING %s' % out_path)
        cd_off = write_apk(out_entries, out_path)
        log('  entries written: %d   central dir @0x%x' % (len(out_entries), cd_off))

        expect = [prefix + 'lib%s.so' % a.libname, prefix + 'lib%s.config.so' % a.libname]
        if a.script:
            expect.append(prefix + 'lib%s.script.so' % a.libname)
        ok = verify(out_path, expect, align)
        log('\n[NEXT] ab DEX patch + zipalign-verify + apksigner:  README_frida_gadget.md §3-§5')
        sys.exit(0 if ok else 1)
    else:
        log('\n[dry-run] kuch likha nahi gaya.')


if __name__ == '__main__':
    main()
