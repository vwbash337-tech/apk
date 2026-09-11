"""Layer 3: native library (ELF) forensics.

`libtopfollow.so` is a 1.8 MB custom library in an app whose Java layer is
plain Jetpack Compose — so whatever is unusual about this app lives here.
This module is a self-contained ELF32/64 reader plus a hardening + behaviour
import table, so it runs anywhere without binwalk/radare2.

Why each check matters
  * PIE / RELRO / canary / NX / FORTIFY  -> how easy the lib is to exploit
  * JNI export names -> the Java->native contract, and thus the lib's purpose
  * dangerous imports (ptrace, /proc, dlopen, socket, execve) -> anti-analysis
    and C2 behaviour that Java-layer analysis cannot see
  * per-section entropy -> encrypted or VM-protected payloads
  * cross-ABI size divergence -> arch-specific obfuscation or dead code
"""

from __future__ import annotations

import os
import re
import struct
from typing import Any

from .core import (
    Finding,
    Findings,
    Sev,
    extract_iocs,
    human,
    iter_strings,
    shannon_entropy,
)

EI_NIDENT = 16
DT_NULL, DT_NEEDED, DT_STRTAB, DT_STRTAB, DT_SYMTAB, DT_JMPREL = 1, 5, 5, 5, 6, 23  # noqa
DT_FLAGS_1, DT_INIT_ARRAY, DT_FINI_ARRAY = 30, 26, 27
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE, PT_GNU_RELRO, PT_GNU_STACK, PT_TLS = 1, 2, 3, 4, 0x6474E552, 0x6474E551, 7
STB_GLOBAL = 1
SHT_PROGBITS, SHT_NOBITS = 1, 8
PF_X, PF_W = 1, 2

# imports that reveal intent when the app has no business doing this
SUSPICIOUS_IMPORTS: dict[str, tuple[str, Sev, str]] = {
    "ptrace": ("Anti-debugging: PTRACE_TRACEME blocks a second debugger/strace", Sev.HIGH, "D4.003"),
    "fork": ("Process spawning from native code", Sev.MEDIUM, "D4.001"),
    "execve": ("Process spawning / possible second-stage payload", Sev.HIGH, "D4.001"),
    "execl": ("Process spawning", Sev.HIGH, "D4.001"),
    "execlp": ("Process spawning", Sev.HIGH, "D4.001"),
    "system": ("Shell command execution", Sev.HIGH, "D4.001"),
    "popen": ("Shell command execution with output capture", Sev.HIGH, "D4.001"),
    "dlopen": ("Runtime library loading (hooking / injecting / unpacking)", Sev.MEDIUM, "D4.002"),
    "dlsym": ("Runtime symbol resolution (classic hidden-API / hook primitive)", Sev.MEDIUM, "D4.002"),
    "mmap": ("Memory mapping (used by packers & shellcode loaders)", Sev.LOW, ""),
    "mprotect": ("Making data executable - self-modifying code / unpacking", Sev.HIGH, "D4.002"),
    "syscall": ("Raw syscalls bypass libc hooks and seccomp logging", Sev.HIGH, "D4.003"),
    "__system_property_get": ("Reads ro.* props, usually emulator/root detection", Sev.MEDIUM, ""),
    "gettimeofday": ("Timing checks for emulators / instrumentation (Frida slows calls)", Sev.LOW, ""),
    "socket": ("Native network I/O - bypasses Java-level proxy & VPN monitoring", Sev.HIGH, "D4.001"),
    "connect": ("Native outbound connections", Sev.HIGH, "D4.001"),
    "getaddrinfo": ("Native DNS resolution", Sev.MEDIUM, "D4.001"),
    "send": ("Native socket write", Sev.MEDIUM, "D4.001"),
    "recv": ("Native socket read", Sev.MEDIUM, "D4.001"),
    "open": ("File open (path in .rodata tells you what)", Sev.LOW, ""),
    "openat": ("File open", Sev.LOW, ""),
    "fopen": ("File open", Sev.LOW, ""),
    "read": ("File read", Sev.LOW, ""),
    "unlink": ("File deletion - self-deleting dropper behaviour", Sev.HIGH, "D4.002"),
    "chmod": ("Permission change on written payload", Sev.MEDIUM, "D4.002"),
    "stat": ("File existence probe (root/Magisk detection)", Sev.LOW, ""),
    "access": ("File existence probe (su/root detection)", Sev.MEDIUM, ""),
    "inotify_init": ("Watching for Frida/Magisk file activity", Sev.MEDIUM, ""),
    "pthread_create": ("Background threads from native code", Sev.LOW, ""),
    "sleep": ("Delays that frustrate dynamic analysis", Sev.LOW, ""),
    "nanosleep": ("Delays that frustrate dynamic analysis", Sev.LOW, ""),
    "madvise": ("Memory hints; used with MAP_JIT-like tricks", Sev.LOW, ""),
    "memcpy": ("", Sev.INFO, ""),
    "exit": ("Forced process exit (anti-analysis tripwire)", Sev.MEDIUM, ""),
    "_exit": ("Forced process exit (anti-analysis tripwire)", Sev.MEDIUM, ""),
    "abort": ("Hard kill on tamper detection", Sev.MEDIUM, ""),
    "inflate": ("Decompression of an embedded payload", Sev.MEDIUM, "D4.002"),
    "EVP_DecryptInit_ex": ("Native symmetric decryption", Sev.HIGH, ""),
    "EVP_EncryptInit_ex": ("Native symmetric encryption", Sev.MEDIUM, ""),
    "EVP_aes_256_cbc": ("AES-256-CBC in native code (config/secret decryption)", Sev.MEDIUM, ""),
    "EVP_aes_128_ctr": ("AES-CTR in native code", Sev.MEDIUM, ""),
    "RSA_public_encrypt": ("Native RSA encryption - typical of key/credential exfil", Sev.HIGH, "D4.001"),
    "RSA_private_decrypt": ("Native RSA private-key operation - embedded private key", Sev.CRITICAL, "D4.002"),
    "HMAC_Init_ex": ("HMAC, e.g. request signing", Sev.MEDIUM, ""),
    "SHA256_Final": ("Hashing, e.g. integrity self-check", Sev.LOW, ""),
    "getpid": ("Debugging self-check (pid == ppid heuristics)", Sev.LOW, ""),
    "getppid": ("Debugging self-check", Sev.LOW, ""),
    "prctl": ("Process name/ptrace scope manipulation", Sev.MEDIUM, ""),
    "personality": ("ADDR_NO_RANDOMIZE -> disables ASLR for a child", Sev.HIGH, "D4.002"),
    "setsid": ("Detaches from controlling terminal: daemonising payload", Sev.MEDIUM, "D4.001"),
    "setresuid": ("Privilege manipulation", Sev.HIGH, ""),
    "setuid": ("Privilege manipulation", Sev.HIGH, ""),
    "unshare": ("Namespace manipulation / sandbox escape attempt", Sev.HIGH, ""),
    "mincore": ("Resident-page probing (anti-VM / self-check)", Sev.MEDIUM, ""),
    "process_vm_readv": ("Reading another process's memory", Sev.CRITICAL, "D4.001"),
    "process_vm_writev": ("Writing another process's memory (injection)", Sev.CRITICAL, "D4.001"),
    "vm_read": ("", Sev.INFO, ""),
}

PROC_PATHS = re.compile(rb"/proc/(?:self|tid|\d+)/(?:maps|status|task|mem|cmdline|exe|fd)")
SU_PATHS = re.compile(rb"/system/xbin/su|/system/bin/su|/sbin/su|/data/local/tmp/su|magisk", re.I)
EMU_TOKENS = re.compile(rb"goldfish|ranchu|genymotion|vbox|qemu|android_x86|nox|bluestacks|dnu|memu", re.I)
HOOK_TOKENS = re.compile(rb"frida|xposed|substrate|gum-js|linjector|gadget|gum|riru|zygisk|lsposed|edxposed", re.I)
EMULATOR_PROPS = re.compile(rb"ro\.kernel\.qemu|ro\.debug\.gem|ro\.build\.qemu|goldfish", re.I)


class Elf:
    """Minimal ELF reader (32/64-bit, LE) good enough for auditing."""

    def __init__(self, blob: bytes, name: str = "?"):
        self.name = name
        self.blob = blob
        if blob[:4] != b"\x7fELF":
            raise ValueError(f"{name}: not an ELF ({blob[:8]!r})")
        self.ei_class = blob[4]
        self.is64 = self.ei_class == 2
        self.endian = "<" if blob[5] == 1 else ">"
        self.machine = struct.unpack_from(self.endian + "H", blob, 18)[0]
        self.version = struct.unpack_from(self.endian + "I", blob, 20)[0]
        self.type = struct.unpack_from(self.endian + "H", blob, 16)[0]
        if self.is64:
            self.entry = struct.unpack_from(self.endian + "Q", blob, 24)[0]
            phoff = struct.unpack_from(self.endian + "Q", blob, 32)[0]
            shoff = struct.unpack_from(self.endian + "Q", blob, 40)[0]
            flags = struct.unpack_from(self.endian + "I", blob, 48)[0]
            phentsize = struct.unpack_from(self.endian + "H", blob, 54)[0]
            phnum = struct.unpack_from(self.endian + "H", blob, 56)[0]
            shentsize = struct.unpack_from(self.endian + "H", blob, 58)[0]
            shnum = struct.unpack_from(self.endian + "H", blob, 60)[0]
            shstrndx = struct.unpack_from(self.endian + "H", blob, 62)[0]
        else:
            self.entry = struct.unpack_from(self.endian + "I", blob, 24)[0]
            phoff = struct.unpack_from(self.endian + "I", blob, 28)[0]
            shoff = struct.unpack_from(self.endian + "I", blob, 32)[0]
            flags = struct.unpack_from(self.endian + "I", blob, 36)[0]
            phentsize = struct.unpack_from(self.endian + "H", blob, 42)[0]
            phnum = struct.unpack_from(self.endian + "H", blob, 44)[0]
            shentsize = struct.unpack_from(self.endian + "H", blob, 46)[0]
            shnum = struct.unpack_from(self.endian + "H", blob, 48)[0]
            shstrndx = struct.unpack_from(self.endian + "H", blob, 50)[0]
        self.flags = flags
        self.Abiflags = flags  # Android stores API level here: low 16 bits = ABI, high = API
        self.api_level = (flags >> 16) & 0xFFFF
        if shentsize < 16 or shoff + shnum * shentsize > len(blob):
            raise ValueError(f"{name}: corrupt section header table (shoff={shoff}, num={shnum})")
        if phentsize < 8 and phnum:
            raise ValueError(f"{name}: corrupt program header table")
        self.sections = self._sections(shoff, shentsize, shnum, shstrndx)
        self.segments = self._segments(phoff, phentsize, phnum)
        self.sh_by_name = {s["name"]: s for s in self.sections}

    def _p(self, off: int, size: int) -> bytes:
        for s in self.segments:
            if s["type"] == PT_LOAD and s["offset"] <= off < s["offset"] + s["filesz"]:
                o = s["offset"] + (off - s["vaddr"])
                return self.blob[o : o + size]
        return b""

    def _strtab_at(self, addr: int) -> bytes:
        # find section containing addr, else map via segments
        for s in self.sections:
            if s["addr"] <= addr < s["addr"] + max(s["size"], 1) and s["type"] != SHT_NOBITS:
                return self.blob[s["off"] : s["off"] + s["size"]]
        return self._p(addr, 4096)

    def _sections(self, off: int, entsz: int, num: int, strndx: int) -> list[dict]:
        out = []
        if not num or strndx >= num:
            return out
        shstr_off = struct.unpack_from(self.endian + ("Q" if self.is64 else "I"), self.blob, off + strndx * entsz + 24)[0]
        shstr_sz = struct.unpack_from(self.endian + ("Q" if self.is64 else "I"), self.blob, off + strndx * entsz + 32)[0]
        shstr = self.blob[shstr_off : shstr_off + shstr_sz]

        def nm(o: int) -> str:
            e = shstr.find(b"\x00", o)
            return shstr[o:e].decode("latin-1") if o < len(shstr) else ""

        for i in range(num):
            b = off + i * entsz
            if b + entsz > len(self.blob):
                break
            if self.is64:
                name, typ, fl, addr, o, sz, link, info, align, entsize = struct.unpack_from(
                    self.endian + "IIQQQQIIQQ", self.blob, b
                )
            else:
                name, typ, fl, addr, o, sz, link, info, align, entsize = struct.unpack_from(
                    self.endian + "10I", self.blob, b
                )
            out.append(
                dict(
                    idx=i,
                    name=nm(name),
                    type=typ,
                    flags=fl,
                    addr=addr,
                    off=o,
                    size=sz,
                    link=link,
                    info=info,
                    entsize=entsize,
                )
            )
        return out

    def _segments(self, off: int, entsz: int, num: int) -> list[dict]:
        out = []
        for i in range(num):
            b = off + i * entsz
            if b + entsz > len(self.blob):
                break
            if self.is64:
                typ, fl, o, vaddr, paddr, fsz, msz, al = struct.unpack_from(self.endian + "IIQQQQQQ", self.blob, b)
            else:
                typ, o, vaddr, paddr, fsz, msz, fl, al = struct.unpack_from(self.endian + "8I", self.blob, b)
            out.append(dict(type=typ, flags=fl, offset=o, vaddr=vaddr, filesz=fsz, memsz=msz, align=al))
        return out

    # ---- dynamic table --------------------------------------------------
    def dynamic(self) -> list[tuple[int, int]]:
        dyn = next((s for s in self.sections if s["name"] == ".dynamic"), None)
        if not dyn:
            for s in self.segments:
                if s["type"] == PT_DYNAMIC:
                    dyn = dict(name=".dynamic", off=s["offset"], size=s["filesz"])
                    break
        if not dyn:
            return []
        ent = 16 if self.is64 else 8
        fmt = self.endian + ("QQ" if self.is64 else "II")
        out = []
        base = dyn["off"]
        for i in range(0, dyn["size"] - ent + 1, ent):
            tag, val = struct.unpack_from(fmt, self.blob, base + i)
            out.append((tag, val))
            if tag == DT_NULL:
                break
        return out

    def needed(self) -> list[str]:
        d = self.dynamic()
        strtab_addr = next((v for t, v in d if t == 5), 0)
        if not strtab_addr:
            return []
        st = self._strtab_at(strtab_addr)
        names = []
        for t, v in d:
            if t == DT_NEEDED and v:
                e = st.find(b"\x00", v - strtab_addr)
                if e > 0:
                    names.append(st[v - strtab_addr : e].decode("latin-1"))
        return names

    def symbols(self) -> tuple[list[tuple[str, int, int]], list[tuple[str, int, int]]]:
        """(exported, undefined) symbol name lists."""
        sym = next((s for s in self.sections if s["name"] == ".dynsym"), None)
        strtab = next((s for s in self.sections if s["name"] == ".dynstr"), None)
        if not sym or not strtab or sym["link"] >= len(self.sections):
            return [], []
        sh = self.sections[sym["link"]]
        strs = self.blob[sh["off"] : sh["off"] + sh["size"]]
        ent = 24 if self.is64 else 16
        fmt = self.endian + ("IIQQ" if self.is64 else "4I")
        exported, undefined = [], []

        def name(o: int) -> str:
            e = strs.find(b"\x00", o)
            return strs[o:e].decode("latin-1", "replace") if o < len(strs) else ""

        for i in range(0, sym["size"] - ent + 1, ent):
            b = sym["off"] + i
            if self.is64:
                nmt, info, other, shndx, value, sz = struct.unpack_from(self.endian + "IBBHQQ", self.blob, b)
            else:
                nmt, value, sz, info, other, shndx = struct.unpack_from(self.endian + "IIIBBH", self.blob, b)
            if shndx == 0:
                undefined.append((name(nmt), value, sz))
            elif (info >> 4) == STB_GLOBAL:
                exported.append((name(nmt), value, sz))
        return exported, undefined


def analyse(libdir: str, F: Findings) -> dict[str, Any]:
    info: dict[str, Any] = {"libs": {}}
    if not os.path.isdir(libdir):
        return info
    files = []
    for root, _, fs in os.walk(libdir):
        for f in fs:
            files.append(os.path.join(root, f))
    natives = sorted(f for f in files if f.endswith(".so"))

    by_name: dict[str, dict[str, Any]] = {}
    all_urls: set[str] = set()
    for p in natives:
        rel = os.path.relpath(p, os.path.dirname(libdir))  # e.g. arm64-v8a/libtopfollow.so
        blob = open(p, "rb").read()
        base = os.path.basename(p)
        try:
            e = Elf(blob, base)
        except (ValueError, struct.error, IndexError, Exception) as ex:
            F.add(
                Finding(
                    "NAT-001",
                    f"{rel}: not a parseable ELF",
                    Sev.MEDIUM,
                    "native",
                    f"{ex}. A .so entry that is not a real ELF is a classic hidden-payload "
                    "hiding place (renamed dex/zip/config behind a .so name).",
                    [rel],
                )
            )
            continue
        rec: dict[str, Any] = {
            "path": rel,
            "size": len(blob),
            "size_h": human(len(blob)),
            "class": "ELF64" if e.is64 else "ELF32",
            "machine": {3: "Intel 80386", 40: "ARM (32-bit)", 62: "AMD x86-64", 183: "ARM aarch64"}.get(e.machine, hex(e.machine)),
            "type": {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN (shared/pie)", 4: "CORE"}.get(e.type, hex(e.type)),
            "entry": hex(e.entry),
            "min_sdk": e.api_level,
            "sections": len(e.sections),
            "entropy": round(shannon_entropy(blob), 3),
        }
        # build-id / comment -> toolchain provenance
        for sn in (".comment", ".note.android.ident", ".note.gnu.build-id"):
            s = e.sh_by_name.get(sn)
            if s:
                data = blob[s["off"] : s["off"] + min(s["size"], 256)]
                txt = bytes(c if 32 <= c < 127 else 32 for c in data).decode("latin-1").strip()
                rec[sn] = txt[:180]

        # ---------- hardening posture ----------
        seg_types = {s["type"] for s in e.segments}
        stack = next((s for s in e.segments if s["type"] == PT_GNU_STACK), None)
        relro = PT_GNU_RELRO in seg_types
        exported, undefined = e.symbols()
        unames = {n for n, _, _ in undefined}
        enames = [n for n, _, _ in exported]
        canary = any("__stack_chk_fail" in n for n in unames)
        fortify = [n for n in unames if "_chk" in n]
        # PIE: shared objects on Android are always ET_DYN, so real check is
        # whether relocations exist (no TEXTREL)
        textrel = any(s["type"] == 23 and False for s in e.sections)  # placeholder
        rec["hardening"] = {
            "nx_stack": bool(stack and not (stack["flags"] & PF_X)),
            "relro": relro,
            "now": any(t == 30 and (v & 0x1) for t, v in e.dynamic()),  # BIND_NOW
            "stack_canary": canary,
            "fortify_src": len(fortify),
            "stripped": not any(s["name"] == ".symtab" for s in e.sections),
            "textrel": bool(e.sh_by_name.get(".rel.text")),
            "symbol_table": any(s["name"] == ".symtab" for s in e.sections),
        }
        hs = rec["hardening"]
        missing = [
            k
            for k, ok in (
                ("stack canary", hs["stack_canary"]),
                ("RELRO", hs["relro"]),
                ("NX stack", hs["nx_stack"]),
                ("FORTIFY", hs["fortify_src"] > 0),
            )
            if not ok
        ]
        if base == "libtopfollow.so" and missing and "arm64" in rel:
            F.add(
                Finding(
                    "NAT-010",
                    f"{rel} missing exploit mitigations: {', '.join(missing)}",
                    Sev.MEDIUM,
                    "native",
                    "This library is reached from Java via JNI with attacker-influenced "
                    "arguments; missing mitigations turn any memory bug in it into code execution "
                    "inside the app process (which then holds the user's session tokens).",
                    [str(hs)],
                    cwe="CWE-693",
                )
            )
        if hs["textrel"]:
            F.add(
                Finding(
                    "NAT-011",
                    f"{rel} has TEXTREL (writable+relocatable text)",
                    Sev.HIGH,
                    "native",
                    "Self-modifying/patchable code segment: the signature of a hand-loaded, "
                    "packed or runtime-patched library. It also defeats W^X.",
                    [str(hs)],
                )
            )

        # ---------- section anomalies ----------
        hi_entropy = []
        for s in e.sections:
            if s["type"] == SHT_NOBITS or s["size"] == 0:
                continue
            data = blob[s["off"] : s["off"] + s["size"]]
            ent = shannon_entropy(data)
            s["entropy"] = round(ent, 3)
            if ent > 7.2 and s["size"] > 4096:
                hi_entropy.append(f".{s['name'].lstrip('.')}={ent:.2f} ({human(s['size'])})")
        rec["high_entropy_sections"] = hi_entropy
        if hi_entropy:
            F.add(
                Finding(
                    "NAT-020",
                    f"{rel}: high-entropy sections (encrypted/packed payload)",
                    Sev.HIGH,
                    "native",
                    "Entropy above ~7.2 bits/byte in a code/rodata section is the classic "
                    "signature of an embedded blob that is decrypted at runtime - the real "
                    "logic is not visible to any static scanner and is only materialised in "
                    "memory while the process runs.",
                    hi_entropy,
                )
            )
        # writable+executable segment
        wx = [
            f"seg{i} flags={s['flags']:#x} sz={human(s['filesz'])}"
            for i, s in enumerate(e.segments)
            if s["type"] == PT_LOAD and (s["flags"] & PF_X) and (s["flags"] & PF_W)
        ]
        rec["wx_segments"] = wx
        if wx:
            F.add(
                Finding(
                    "NAT-021",
                    f"{rel}: segment is both WRITABLE and EXECUTABLE",
                    Sev.CRITICAL,
                    "native",
                    "W^X violation. Combined with mprotect/mmap imports this is a "
                    "shellcode/decrypted-payload loader pattern, not normal app code.",
                    wx,
                    attack=["D4.002 - Resilience / code loading"],
                )
            )
        vmp = [s["name"] for s in e.sections if re.match(r"\.vmp|\.themida|\.enigma|\.aspack|\.petite|\.hhc", s["name"] or "", re.I)]
        if vmp:
            F.add(
                Finding(
                    "NAT-022",
                    f"{rel} shows commercial-protector section names",
                    Sev.HIGH,
                    "native",
                    "Sections " + ", ".join(vmp) + " are written by VMProtect/Themida-class "
                    "packers. Legitimate mobile apps essentially never ship these; they exist to "
                    "defeat RE of exactly the credential/crypto logic we are looking for.",
                    vmp,
                )
            )
        init_arr = e.sh_by_name.get(".init_array")
        rec["init_array_entries"] = (init_arr["size"] // (8 if e.is64 else 4)) if init_arr else 0
        rec["needed"] = e.needed()
        rec["exported_count"] = len(enames)
        rec["undefined_count"] = len(unames)

        # ---------- JNI contract ----------
        jni = [n for n in enames if n.startswith("Java_")]
        rec["jni_exports"] = jni[:60]
        if jni:
            F.add(
                Finding(
                    "NAT-030",
                    f"{rel} exports {len(jni)} static JNI symbols",
                    Sev.INFO,
                    "native",
                    "Static registration means the Java-side class/method names are burned "
                    "into the .so; the obfuscated Java layer is therefore re-linkable from here.",
                    jni[:25],
                    refs=["decode Java_<mangled> -> com/example/Class.method"],
                )
            )
        on_load = [n for n in enames if n in ("JNI_OnLoad", "JNI_OnUnload")]
        rec["has_jni_onload"] = bool(on_load)
        if on_load:
            F.add(
                Finding(
                    "NAT-031",
                    f"{rel} uses JNI_OnLoad dynamic registration",
                    Sev.MEDIUM,
                    "native",
                    "Methods are registered at load time via RegisterNatives, so the Java<->native "
                    "mapping is built at runtime and there is nothing to grep. This is a deliberate "
                    "anti-static-analysis choice.",
                    on_load,
                )
            )

        # ---------- dangerous imports ----------
        hits: list[tuple[str, str, Sev]] = []
        for sym, (why, sev, atk) in SUSPICIOUS_IMPORTS.items():
            if sym in unames or any(n.startswith(sym + "_") for n in unames):
                if why:
                    hits.append((sym, why, sev))
        rec["suspicious_imports"] = [{"sym": s, "why": w, "sev": v.name} for s, w, v in hits]
        for sym, why, sev in hits:
            F.add(
                Finding(
                    "NAT-040:" + sym,
                    f"{rel} imports {sym}()",
                    sev,
                    "native",
                    why,
                    [sym],
                    attack=[a for a in (SUSPICIOUS_IMPORTS.get(sym, ("", Sev.LOW, ""))[2],) if a],
                )
            )

        # ---------- strings & IOCs in native space ------------------------
        iocs = extract_iocs(blob)
        urls = [u for u in iocs["urls"]]
        all_urls.update(urls)
        rec["native_urls"] = urls[:60]
        rec["native_pem"] = iocs["pem"][:5]
        rec["native_emails"] = iocs["emails"][:20]
        rec["native_hexkeys"] = iocs["hexblobs"][:20]

        # anti-analysis string markers
        found_proc = sorted({m.group(0).decode() for m in PROC_PATHS.finditer(blob)})[:20]
        found_su = sorted({m.group(0).decode() for m in SU_PATHS.finditer(blob)})[:20]
        found_hook = sorted({m.group(0).decode() for m in HOOK_TOKENS.finditer(blob)})[:20]
        found_emu = sorted({m.group(0).decode() for m in EMU_TOKENS.finditer(blob)})[:20]
        found_props = sorted({m.group(0).decode() for m in EMULATOR_PROPS.finditer(blob)})[:20]
        rec["proc_paths"] = found_proc
        rec["su_paths"] = found_su
        rec["hook_strings"] = found_hook
        rec["emulator_strings"] = found_emu
        rec["emulator_props"] = found_props

        if found_proc and ("ptrace" in unames or "access" in unames or "fopen" in unames):
            F.add(
                Finding(
                    "NAT-050",
                    f"{rel} reads /proc for anti-analysis",
                    Sev.HIGH,
                    "native",
                    "Scanning /proc/self/maps (or /proc/self/status TracerPid) is how a library "
                    "detects Frida/Xposed/strace and refuses to run - which also means the code "
                    "it is hiding is only revealed once those tools are removed.",
                    found_proc,
                    attack=["D4.003 - Anti-analysis / anti-debugging"],
                )
            )
        if found_su:
            F.add(
                Finding(
                    "NAT-051",
                    f"{rel} probes for root/su binaries",
                    Sev.MEDIUM,
                    "native",
                    "Root probing in a follower-app has no legitimate use; its purpose is to "
                    "refuse to run (or alter behaviour) on a device that can inspect it.",
                    found_su,
                    attack=["D4.003"],
                )
            )
        if found_hook:
            F.add(
                Finding(
                    "NAT-052",
                    f"{rel} contains hooking-framework signatures",
                    Sev.HIGH,
                    "native",
                    "Explicit frida/xposed/substrate detection = counter-intelligence against "
                    "the analysis, not a feature.",
                    found_hook,
                )
            )
        if found_emu or found_props:
            F.add(
                Finding(
                    "NAT-053",
                    f"{rel} fingerprints emulators",
                    Sev.MEDIUM,
                    "native",
                    "Emulator checks in this class of app exist to hide behaviour from "
                    "sandboxes (Triage, Any.Run, MobSF) so automated verdicts come back clean.",
                    (found_emu + found_props)[:20],
                    attack=["D4.003"],
                )
            )
        if iocs["pem"]:
            F.add(
                Finding(
                    "NAT-060",
                    f"{rel} embeds PEM key material",
                    Sev.HIGH,
                    "native",
                    "An embedded public key is used to verify server responses or encrypt "
                    "harvested credentials; an embedded private key is an outbound-signing "
                    "identity for the operator's bot fleet.",
                    [p[:120] for p in iocs["pem"]],
                )
            )
        if urls:
            third = [u for u in urls if "google" not in u and "android" not in u and "apache" not in u]
            if third:
                F.add(
                    Finding(
                        "NAT-061",
                        f"{rel} contains hard-coded non-Google endpoints",
                        Sev.HIGH,
                        "network",
                        "Native-code endpoints bypass Java-level proxying and are where the "
                        "operator's real backend usually lives.",
                        third[:25],
                        attack=["D4.001 - C2 / exfiltration channel"],
                    )
                    )
        by_name[rel] = rec
        info["libs"][rel] = rec

    # ---------- cross-ABI divergence ----------
    per_base: dict[str, dict[str, int]] = {}
    for rel, rec in by_name.items():
        _, base = rel.split("/", 1)
        per_base.setdefault(base, {})[rel.split("/")[0]] = rec["size"]
    info["abi_sizes"] = per_base
    for base, sizes in per_base.items():
        vals = list(sizes.values())
        if len(vals) > 1 and max(vals) > 1.4 * min(vals):
            F.add(
                Finding(
                    "NAT-070",
                    f"{base} sizes diverge sharply across ABIs",
                    Sev.MEDIUM,
                    "native",
                    "Same source, wildly different machine code size is expected for obfuscated "
                    "or arch-tuned anti-analysis code; for ordinary NDK code the ratio is ~1.2-1.4x. "
                    "Worth diffing the exports of each copy.",
                    [f"{k}: {human(v)}" for k, v in sizes.items()],
                )
            )

    info["all_native_urls"] = sorted(all_urls)
    return info
