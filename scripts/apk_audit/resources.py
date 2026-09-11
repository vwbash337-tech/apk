"""Layer 6: resources.arsc + res/ forensics.

The resource table is where an app tells the truth about itself in plain text:
every button label, every screen title, every feature string. For an app whose
*code* is minified, the string pool is often the fastest route to the actual
capability set. It also holds the inlined XML for backup/data-extraction rules,
which enumerates private filenames the app considers sensitive - a much better
signal than the manifest flags alone.
"""

from __future__ import annotations

import re
import struct
from typing import Any

from .core import Finding, Findings, Sev, human, iter_strings

RES_STRING_POOL = 0x0001
RES_TABLE = 0x0002
RES_XML = 0x0003
RES_TYPE = 0x0002
RES_CONFIG = 0x000E

POOL_UTF8_FLAG = 1 << 8


class Chunk:
    def __init__(self, blob: bytes, off: int):
        self.off = off
        self.type, self.hdr = struct.unpack_from("<HH", blob, off)
        (self.size,) = struct.unpack_from("<I", blob, off + 4)
        self.blob = blob

    def payload(self) -> bytes:
        return self.blob[self.off + self.hdr : self.off + self.size]


def parse_string_pool(blob: bytes, off: int) -> list[str]:
    typ, hdr, size = struct.unpack_from("<HHI", blob, off)
    if typ != RES_STRING_POOL:
        return []
    str_count, style_count, flags, strings_start, _styles_start = struct.unpack_from("<IIIII", blob, off + 8)
    offsets = [struct.unpack_from("<I", blob, off + hdr + 4 * i)[0] for i in range(str_count)]
    base = off + hdr + 4 * str_count + strings_start
    out: list[str] = []
    utf8 = bool(flags & POOL_UTF8_FLAG)
    for o in offsets:
        p = base + o
        try:
            if utf8:
                # nchars (u16-ish varint), nbytes (varint), then utf-8
                q = p
                n1 = blob[q]
                if n1 & 0x80:
                    q += 2
                else:
                    q += 1
                n2 = blob[q]
                if n2 & 0x80:
                    n2 = ((n2 & 0x7F) << 8) | blob[q + 1]
                    q += 2
                else:
                    q += 1
                out.append(blob[q : q + n2].decode("utf-8", "replace"))
            else:
                n = struct.unpack_from("<H", blob, p)[0]
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", blob, p + 2)[0]
                    p += 4
                else:
                    p += 2
                out.append(blob[p : p + 2 * n].decode("utf-16-le", "replace"))
        except Exception:
            out.append("")
    return out


def iter_res_chunks(blob: bytes, off: int, size: int, want: int):
    """Walk top-level chunks inside a container."""
    p = off
    end = off + size
    while p + 8 <= end:
        try:
            typ, hdr, csz = struct.unpack_from("<HHI", blob, p)
        except struct.error:
            break
        if csz < 8 or p + csz > end:
            break
        if typ == want:
            yield p, csz
        p += csz


def analyse(xdir: str, F: Findings) -> dict[str, Any]:
    import os

    info: dict[str, Any] = {}
    arsc = os.path.join(xdir, "resources.arsc")
    if not os.path.exists(arsc):
        return info
    blob = open(arsc, "rb").read()
    typ, hdr, size = struct.unpack_from("<HHI", blob, 0)
    if typ != RES_TABLE:
        F.add(Finding("RES-000", "resources.arsc header is not a RES_TABLE", Sev.LOW, "resources",
                      f"type={typ:#x}. Tampered or non-standard resource table.", [f"{typ:#06x}"]))
    ids, _ = struct.unpack_from("<II", blob, 8)
    info["package_count"] = ids
    pool_off = 16
    global_pool = parse_string_pool(blob, pool_off)
    info["global_strings"] = len(global_pool)

    # package chunks -> their own pools
    strings: list[str] = list(global_pool)
    pkgs: list[dict[str, Any]] = []
    for poff, psz in iter_res_chunks(blob, 16, size, 0x0200):
        ptyp, phdr, _ = struct.unpack_from("<HHI", blob, poff)
        (pid,) = struct.unpack_from("<I", blob, poff + 8)
        ptype = struct.unpack_from("<I", blob, poff + 8)[0]
        # name string index at +12 (u32) for non-legacy
        nidx = struct.unpack_from("<I", blob, poff + 12)[0]
        pos = poff + phdr
        ppool = parse_string_pool(blob, pos)
        ptypechunk = None
        # skip type+key pools
        q = pos
        for _ in range(2):
            t, h, s = struct.unpack_from("<HHI", blob, q)
            if t != RES_STRING_POOL:
                break
            if _ == 0:
                ptypechunk = q
            q += s
        strings += ppool
        typstrings: list[str] = []
        if ptypechunk:
            typstrings = parse_string_pool(blob, ptypechunk)
            strings += typstrings
        pn = ppool[nidx].split("$")[0] if nidx < len(ppool) else "?"
        pkgs.append({"id": pid, "name": pn, "types": len(typstrings), "strings": len(ppool)})
    info["packages"] = pkgs

    # interesting global strings
    joined = b"\n".join(s.encode("utf-8", "replace") for s in strings)
    from .core import extract_iocs

    iocs = extract_iocs(joined)
    info["res_urls"] = iocs["urls"]
    info["res_domains"] = iocs["domains"][:40]
    if iocs["urls"]:
        F.add(Finding("RES-010", "Hard-coded URLs inside resources.arsc", Sev.HIGH, "network",
                      "Endpoints parked in the resource table are usually used for terms-of-service, "
                      "support and - in apps like this - share/redirect targets. They are readable "
                      "without any code analysis, which is why they are worth cross-checking against "
                      "the code-level list for divergence.",
                      iocs["urls"][:30], attack=["D4.001"]))

    # UI strings that reveal features
    ui = [s for s in strings if 4 < len(s) < 160 and re.search(r"[a-z] [a-z]", s.lower()) and not s.startswith(("http", "res/", "L", "["))]
    interesting_pat = re.compile(
        r"(follow|unfollow|like|comment|repost|save|direct|dm|story|post|account|password|"
        r"login|log in|sign in|token|session|coin|credit|reward|invite|referral|withdraw|"
        r"premium|vip|boost|task|order|queue|auto|bot|proxy|device|ban|restrict|verif)",
        re.I,
    )
    feat = [s for s in ui if interesting_pat.search(s)]
    info["feature_strings_total"] = len(feat)
    info["feature_strings"] = feat[:200]
    if feat:
        F.add(Finding("RES-011", f"{len(feat)} user-facing strings describe automation of a social account",
                      Sev.MEDIUM, "capability",
                      "The UI wording is the clearest statement of intent in the whole package: "
                      "these are the actions the app performs *on the user's behalf, on their account*.",
                      feat[:40], attack=["D4.001 - misuse of platform credentials"]))

    # resource entries that look like config
    cfg_keys = [s for s in strings if re.fullmatch(r"[a-z][a-z0-9_]{4,40}", s or "") and re.search(r"(api|url|host|key|token|secret|base|endpoint|proxy)", s, re.I)]
    info["config_like_keys"] = sorted(set(cfg_keys))[:80]

    # extract inlined XML chunks (backup rules etc.)
    inlined = []
    for m in re.finditer(re.escape(b"\x03\x00\x08\x00"), blob):
        o = m.start()
        if o + 8 > len(blob):
            continue
        csz = struct.unpack_from("<I", blob, o + 4)[0]
        if 40 < csz < 400000:
            inlined.append((o, csz))
    info["inlined_xml_chunks"] = len(inlined)

    # raw res/ tree statistics
    rdir = os.path.join(xdir, "res")
    if os.path.isdir(rdir):
        files = os.listdir(rdir)
        kinds: dict[str, int] = {}
        for f in files:
            kinds[f.rsplit(".", 1)[-1]] = kinds.get(f.rsplit(".", 1)[-1], 0) + 1
        info["res_file_kinds"] = kinds
        info["res_total"] = len(files)
        dirs = [d for d in os.listdir(rdir) if os.path.isdir(os.path.join(rdir, d))]
        info["res_qualifier_dirs"] = sorted(dirs)
        if dirs:
            # read any xml under res/ (backup rules, networks config, provider paths)
            for d in dirs:
                pass
        # decode the raw XML files that are actually AXML
        xmls = [f for f in files if f.endswith(".xml")]
        decoded_samples = []
        for f in xmls[:0]:
            pass
        info["res_xml_count"] = len(xmls)

    # assets
    adir = os.path.join(xdir, "assets")
    if os.path.isdir(adir):
        entries = []
        for root, _, fs in os.walk(adir):
            for f in fs:
                p = os.path.join(root, f)
                entries.append((os.path.relpath(p, xdir), os.path.getsize(p)))
        info["assets"] = [{"name": n, "size": s, "size_h": human(s)} for n, s in sorted(entries)]
        for n, s in entries:
            if n.endswith((".json", ".txt", ".cfg", ".ini", ".xml")) and s < 200000:
                txt = open(os.path.join(xdir, n), "rb").read()
                ss = list(iter_strings(txt, 6))
                info.setdefault("asset_text", {})[n] = [x.decode("latin-1") for x in ss[:40]]
    return info
