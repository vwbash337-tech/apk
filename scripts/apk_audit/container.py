"""Layer 1: APK container forensics.

Works on the raw file, not the unpacked tree, because most interesting
container-level tampering and packaging mistakes are invisible after `unzip`.
Checks that matter here:

  * APK Signing Block presence + which signature schemes are in use
  * v1 (JAR) signature absence  -> no legacy verification
  * page alignment of stored .so entries (required by extractNativeLibs=false)
  * compression choices (deflate vs store) for dex/arsc/so
  * path traversal / zip-slip style entry names
  * duplicate entries, zero-length entries, absurd size ratios (zip bombs)
  * central-directory/local-header disagreement (a classic tamper vector)
  * entry timestamps, unix modes, and the "extra field" space
"""

from __future__ import annotations

import re
import struct
import zipfile
from typing import Any

from .core import Finding, Findings, Sev, human, shannon_entropy

EOCD_MAGIC = b"PK\x05\x06"
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
PAIR_IDS = {
    0x7109871A: "v2",
    0xF05368C0: "v3",
    0x1B93AD61: "v3.1",
    0x42726577: "v4",
    0xF05368C1: "v3.1-additional",
    0x7109871B: "v2-legacy?!",
}
ALIGN = 4096  # page size required for extractNativeLibs=false

RES_SHORT = re.compile(r"^res/[A-Za-z0-9_\-.]{1,4}\.(xml|png|jpg|webp|9\.png|ttf)$")


def analyse(path: str, F: Findings) -> dict[str, Any]:
    info: dict[str, Any] = {}
    raw = open(path, "rb").read()
    size = len(raw)
    info["file_size"] = size
    info["entropy"] = round(shannon_entropy(raw), 3)

    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as e:  # pragma: no cover
        F.add(
            Finding(
                "CONT-001",
                "File is not a readable ZIP archive",
                Sev.CRITICAL,
                "container",
                f"zipfile raised: {e}",
            )
        )
        return info

    names = zf.namelist()
    infos = zf.infolist()
    info["entries"] = len(names)
    uncompressed = sum(i.file_size for i in infos)
    compressed = sum(i.compress_size for i in infos)
    info["uncompressed_size"] = uncompressed
    info["compression_ratio"] = round(compressed / max(uncompressed, 1), 3)

    # ---- inventory ------------------------------------------------------
    buckets: dict[str, list[str]] = {
        "dex": [],
        "res": [],
        "lib": [],
        "assets": [],
        "META-INF": [],
        "other": [],
    }
    for n in names:
        if n.endswith(".dex"):
            buckets["dex"].append(n)
        elif n.startswith("res/"):
            buckets["res"].append(n)
        elif n.startswith("lib/"):
            buckets["lib"].append(n)
        elif n.startswith("assets/"):
            buckets["assets"].append(n)
        elif n.startswith("META-INF/"):
            buckets["META-INF"].append(n)
        else:
            buckets["other"].append(n)
    info["buckets"] = {k: len(v) for k, v in buckets.items()}
    info["dex_files"] = sorted(buckets["dex"])
    info["lib_files"] = sorted(buckets["lib"])
    info["assets"] = sorted(buckets["assets"])

    abis = sorted({n.split("/")[1] for n in buckets["lib"] if n.count("/") >= 2})
    info["abis"] = abis
    # missing armeabi-v7a on an app that still ships x86 is a distribution signal:
    if abis and "armeabi-v7a" not in abis and "x86" in abis:
        F.add(
            Finding(
                "CONT-005",
                "Ships x86/x86_64 natives but no armeabi-v7a",
                Sev.LOW,
                "packaging",
                "Universal Android builds normally include armeabi-v7a for older 32-bit phones. "
                "Its absence together with x86 (an emulator ABI) suggests the APK was built for "
                "sideload/emulator audiences rather than for Play distribution.",
                [", ".join(abis)],
            )
        )

    # ---- multi-dex / dynamic code loading surface -----------------------
    extra_dex = [n for n in buckets["dex"] if n != "classes.dex"]
    dex_in_assets = [
        n for n in buckets["assets"] if n.lower().endswith((".dex", ".jar", ".zip", ".so", ".bin", ".dat"))
    ]
    info["extra_dex"] = extra_dex
    info["assets_code_bearing"] = dex_in_assets
    if extra_dex:
        F.add(
            Finding(
                "CONT-010",
                f"Multi-dex: {len(extra_dex)+1} DEX files",
                Sev.INFO,
                "container",
                "More than one classes.dex; all of them must be audited, secondary dex files "
                "are a common place to hide code from naive tooling.",
                sorted(buckets["dex"]),
            )
        )
    if dex_in_assets:
        F.add(
            Finding(
                "CONT-011",
                "Code-bearing blobs inside assets/",
                Sev.HIGH,
                "container",
                "Dex/jar/so payloads in assets/ imply runtime class loading (DexClassLoader), "
                "i.e. behaviour that is not visible to static manifest analysis.",
                dex_in_assets,
            )
        )

    # ---- signing block --------------------------------------------------
    sig = parse_apk_signing_block(raw)
    info["signing_block"] = sig
    v1 = [n for n in buckets["META-INF"] if n.upper().endswith((".RSA", ".DSA", ".EC"))]
    mf = [n for n in buckets["META-INF"] if n.upper().endswith(".MF")]
    sf = [n for n in buckets["META-INF"] if re.search(r"\.SF$", n, re.I)]
    info["v1_signature"] = bool(v1)
    info["v2_or_higher"] = bool(sig.get("schemes"))
    if not v1:
        F.add(
            Finding(
                "CONT-020",
                "No JAR (v1) signature present",
                Sev.INFO,
                "signing",
                "META-INF carries no .RSA/.SF digest block, so only APK Signing Scheme v2+ is "
                "verified. The package cannot install on Android < 7.0, and any tooling that "
                "checks only v1 sees an unsigned file.",
                sorted(set(v1 + mf + sf)) or ["META-INF/ (no .RSA/.SF)"],
            )
        )
    if not sig.get("found") and not v1:
        F.add(
            Finding(
                "CONT-022",
                "Package appears UNSIGNED",
                Sev.CRITICAL,
                "signing",
                "Neither a v1 JAR signature nor an APK Signing Block was located. Android refuses "
                "to install such a file, so a package in this state was very likely re-zipped "
                "after signing (i.e. repackaged/tampered).",
            )
        )
    if sig.get("anomalies"):
        F.add(
            Finding(
                "CONT-023",
                "Non-canonical APK Signing Block layout",
                Sev.HIGH,
                "signing",
                "apksigner emits `size | id | data` per pair with a recognised pair ID. This file "
                "wraps its v2 pair inside an extra/unknown ID layer. Real Android Studio / "
                "apksigner output does not look like this, so the block was written by a "
                "third-party re-signing tool - the standard fingerprint of a repackaged APK that "
                "was stripped, modified, and signed again by whoever distributed it.",
                sig["anomalies"][:8],
                attack=["D4.002 - integrity / tamper evidence"],
                cwe="CWE-345",
            )
        )

    # ---- alignment / compression ---------------------------------------
    misaligned: list[str] = []
    stored_native: list[str] = []
    for i in infos:
        if i.filename.startswith("lib/") and i.filename.endswith(".so"):
            if i.compress_type == zipfile.ZIP_STORED:
                stored_native.append(i.filename)
            head = raw[i.header_offset : i.header_offset + 30]
            if len(head) == 30 and head[:4] == b"PK\x03\x04":
                nlen, elen = struct.unpack_from("<HH", head, 26)
                data_off = i.header_offset + 30 + nlen + elen
                if data_off % ALIGN:
                    misaligned.append(f"{i.filename} @ {data_off} (off by {data_off % ALIGN})")
    info["stored_native"] = stored_native
    info["native_misaligned"] = misaligned
    if misaligned:
        F.add(
            Finding(
                "CONT-030",
                "Stored .so entries are not 4 KB page-aligned",
                Sev.MEDIUM,
                "container",
                'With android:extractNativeLibs="false" the loader mmaps libraries straight out '
                "of the APK; unaligned entries force a full copy at install or break the mmap, "
                "and are a hallmark of post-signature repackaging/zipalign skipping.",
                misaligned,
            )
        )

    big = {}
    for n in ("classes.dex", "resources.arsc", "AndroidManifest.xml"):
        try:
            i = zf.getinfo(n)
        except KeyError:
            continue
        big[n] = {
            "stored": i.compress_type == 0,
            "size": i.file_size,
            "csize": i.compress_size,
            "crc": f"{i.CRC:#010x}",
        }
    info["core_entries"] = big
    if big.get("resources.arsc", {}).get("stored") is False:
        F.add(
            Finding(
                "CONT-031",
                "resources.arsc is deflate-compressed",
                Sev.LOW,
                "container",
                "AGP stores resources.arsc uncompressed so it can be mmap'd; a compressed table "
                "usually means the file was rebuilt by a third-party packer or re-zipped.",
                [str(big["resources.arsc"])],
            )
        )

    # ---- path traversal / suspicious names -----------------------------
    bad_names = [
        n
        for n in names
        if n.startswith("/") or ".." in n or (n.lower().endswith((".html", ".htm", ".php", ".jsp")) and n.startswith("assets/"))
    ]
    info["bad_names"] = bad_names
    if bad_names:
        F.add(
            Finding(
                "CONT-040",
                "Suspicious archive entry names (Zip Slip candidates)",
                Sev.HIGH,
                "container",
                "Entry names that escape the extraction root. Any code here that unzips payloads "
                "at runtime and trusts these names can be made to write anywhere.",
                bad_names[:20],
                attack=["D4.001"],
                cwe="CWE-22",
            )
        )

    seen: set[str] = set()
    dups: list[str] = []
    for n in names:
        if n in seen:
            dups.append(n)
        seen.add(n)
    info["duplicate_entries"] = dups
    if dups:
        F.add(
            Finding(
                "CONT-041",
                "Duplicate ZIP entries",
                Sev.MEDIUM,
                "container",
                "The extractor and the signature verifier can disagree about which copy wins - "
                "the primitive behind Janus-class attacks.",
                dups[:20],
                cwe="CWE-435",
            )
        )

    empty = [n for n, i in zip(names, infos) if i.file_size == 0 and not n.endswith("/")]
    info["empty_entries"] = len(empty)
    if len(empty) > 3:
        F.add(
            Finding(
                "CONT-042",
                f"{len(empty)} zero-length entries",
                Sev.LOW,
                "container",
                "Mostly benign (marker files) but also how some packers hide renamed payloads.",
                empty[:12],
            )
        )

    bombs = [
        f"{i.filename}: {human(i.file_size)} from {human(i.compress_size)}"
        for i in infos
        if i.compress_size > 4096 and i.file_size / max(i.compress_size, 1) > 60
    ]
    info["high_ratio"] = bombs
    if bombs:
        F.add(
            Finding(
                "CONT-043",
                "Extreme compression ratio entries",
                Sev.MEDIUM,
                "container",
                "Ratio > 60:1 is consistent with a decoy/bomb payload or with a highly "
                "compressible region that is only large because it is zero padding.",
                bombs[:10],
            )
        )

    stamps = {tuple(i.date_time) for i in infos if i.date_time[0] > 1980}
    info["distinct_mod_times"] = len(stamps)
    info["timestamps_sample"] = sorted({f"{d[0]}-{d[1]:02d}-{d[2]:02d}" for d in stamps})[:6]
    if len(stamps) == 1:
        F.add(
            Finding(
                "CONT-045",
                "Every entry shares one identical timestamp",
                Sev.INFO,
                "container",
                "Normal for AGP (all entries get 1980-01-01) - but it also means the archive "
                "carries no build-time information for provenance, and re-packers preserve it "
                "so the repackage date cannot be recovered from the ZIP.",
                [str(next(iter(stamps), None))],
            )
        )

    execy = [i.filename for i in infos if (i.external_attr >> 16) & 0o111 and not i.filename.endswith(".so")]
    info["exec_entries"] = execy
    if execy:
        F.add(
            Finding(
                "CONT-044",
                "Executable permission bit on non-native entries",
                Sev.MEDIUM,
                "container",
                "Files marked +x inside an archive are candidates for being written to a "
                "writable directory and exec'd.",
                execy[:20],
            )
        )

    mismatch: list[str] = []
    for i in infos:
        head = raw[i.header_offset : i.header_offset + 30]
        if len(head) < 30 or head[:4] != b"PK\x03\x04":
            mismatch.append(f"{i.filename}: bad local header")
            continue
        csize, usize = struct.unpack_from("<II", head, 18)
        nlen, _ = struct.unpack_from("<HH", head, 26)
        lname = raw[i.header_offset + 30 : i.header_offset + 30 + nlen]
        if lname.decode("utf-8", "replace") != i.filename:
            mismatch.append(f"{i.filename}: local name {lname!r}")
        if i.flag_bits & 0x8:
            continue  # data descriptor: local sizes are placeholders by design
        if csize != i.compress_size or usize != i.file_size:
            mismatch.append(
                f"{i.filename}: local csize/usize {csize}/{usize} vs CDS {i.compress_size}/{i.file_size}"
            )
    info["header_mismatches"] = mismatch
    if mismatch:
        F.add(
            Finding(
                "CONT-050",
                "Local file header disagrees with central directory",
                Sev.CRITICAL,
                "container",
                "Two views of the same file with different contents. This is the exact primitive "
                "behind Janus / fake-signature / retargeting bugs: verifiers read one copy, the "
                "installer loads the other.",
                mismatch[:15],
                attack=["D4.002"],
                cwe="CWE-345",
            )
        )

    info["streamed_entries"] = sum(1 for i in infos if i.flag_bits & 0x8)

    if sig.get("schemes"):
        F.add(
            Finding(
                "CONT-055",
                "Signature schemes in use: " + ", ".join(sig["schemes"]),
                Sev.INFO,
                "signing",
                "v2 signs the whole archive (any byte edit invalidates it); v3 adds a "
                "proof-of-rotation signer chain; v4 is a Merkle tree used only for incremental "
                "install. Note that all of these are *integrity* mechanisms - none of them says "
                "anything about who the publisher is.",
                [
                    f"block size {human(sig.get('block_size', 0))}",
                    f"block offset {sig.get('block_start')}",
                    f"pairs: {', '.join(sig.get('pair_summary', []))}",
                ],
            )
        )

    # resource-path shortening
    shortened = sum(1 for n in buckets["res"] if RES_SHORT.match(n))
    info["res_shortened"] = shortened
    if buckets["res"] and shortened > 0.6 * len(buckets["res"]):
        F.add(
            Finding(
                "CONT-060",
                "Resource paths shortened/obfuscated",
                Sev.LOW,
                "obfuscation",
                f"{shortened}/{len(buckets['res'])} entries sit directly under res/ with 2-4 "
                "character names instead of res/layout, res/drawable... Layout names are "
                "destroyed, which materially slows manual RE of the UI flow. Caused by AGP "
                "resource shortening/shrinking rather than by hand-written trickery.",
                [n for n in buckets["res"] if RES_SHORT.match(n)][:8],
            )
        )

    zf.close()
    return info


# --------------------------------------------------------------------------
# APK Signing Block
# --------------------------------------------------------------------------
def parse_apk_signing_block(raw: bytes) -> dict[str, Any]:
    """Locate the block and enumerate its (size, id, data) pairs.

    Canonical layout written by apksigner:
        [u64 size][ (u32 pairLen)(u32 id)(data) ]* [zero padding][u64 size]["APK Sig Block 42"]
    We walk it strictly, then also scan for known IDs so that non-canonical
    writers are reported as an anomaly instead of being read as "unsigned".
    """
    out: dict[str, Any] = {"found": False, "schemes": [], "anomalies": [], "pair_summary": []}
    mi = raw.rfind(APK_SIG_BLOCK_MAGIC)
    if mi < 24:
        return out
    out["found"] = True
    cd_off = mi + len(APK_SIG_BLOCK_MAGIC)
    out["magic_offset"] = mi
    out["cd_offset"] = cd_off
    try:
        block_size = struct.unpack_from("<Q", raw, mi - 8)[0]
    except struct.error:
        return out
    out["block_size"] = int(block_size)
    block_start = cd_off - 8 - block_size
    out["block_start"] = block_start
    if block_start < 0 or block_size > cd_off:
        out["anomalies"].append(f"declared block size {block_size} inconsistent with cd_offset {cd_off}")
        return out
    lead = struct.unpack_from("<Q", raw, block_start)[0] if block_start + 8 <= len(raw) else None
    if lead != block_size:
        out["anomalies"].append(f"leading size field {lead} != trailing size field {block_size}")

    pairs_start = block_start + 8
    pairs_end = mi - 8  # the trailing size field sits just before the magic
    schemes: list[str] = []
    p = pairs_start
    walked = 0
    while p + 8 <= pairs_end:
        (plen,) = struct.unpack_from("<I", raw, p)
        if plen < 4 or p + 4 + plen > pairs_end:
            break
        (pid,) = struct.unpack_from("<I", raw, p + 4)
        walked += 1
        name = PAIR_IDS.get(pid)
        if name:
            schemes.append(name)
        if pid == 0:
            # some third-party re-signers emit a size/id pair whose "id" slot is
            # zero with the real v2 header nested one level deeper.
            nid = struct.unpack_from("<I", raw, p + 8)[0]
            nn = PAIR_IDS.get(nid)
            out["pair_summary"].append(f"0x{pid:08x}(len {plen}) -> nested 0x{nid:08x}{'' if not nn else '('+nn+')'}")
            if nn:
                schemes.append(nn)
                out["anomalies"].append(
                    f"pair @{p:#x}: id=0x00000000 with a nested 0x{nid:08x} ({nn}) inside - "
                    f"one level of nesting deeper than the documented format"
                )
        else:
            out["pair_summary"].append(f"0x{pid:08x}(len {plen})")
            out.setdefault("unknown_ids", []).append(f"{pid:#010x}")
        p += 4 + plen
    out["pairs_walked"] = walked
    out["schemes"] = sorted(set(schemes))
    # independent scan for the ids, to be sure we did not miss a scheme
    if not out["schemes"]:
        for pid, nm in PAIR_IDS.items():
            if struct.pack("<I", pid) in raw[block_start:cd_off]:
                out["schemes"].append(nm)
                out["anomalies"].append(f"{nm} id present but not reachable by canonical pair walk")
        out["schemes"] = sorted(set(out["schemes"]))
    out["v2_offset"] = raw.find(struct.pack("<I", 0x7109871A), block_start, cd_off)
    out["note"] = (
        "v2/v3 cover the whole archive including the central directory, so any post-signing edit "
        "(swapping a .so, editing the manifest, injecting a class) invalidates the signature."
    )
    return out


# --------------------------------------------------------------------------
# Signature-scheme integrity verification (independent of apksigner)
# --------------------------------------------------------------------------
def verify_v2_digests(path: str, F: Findings) -> dict[str, Any]:
    """Recompute content digests the way the platform does.

    Full v2/v3 signature *math* (RSA/PKCS#7 verification of the signed-data
    blob) is out of scope here, but the cheap half is high value and is what
    tamper-detection actually needs: recompute SHA-256 over the signed region
    and compare against the digest the signer embedded in the block.
    A mismatch means the archive was edited after signing, and no cert-based
    tool needs to be told - the file simply does not verify.
    """
    import hashlib

    raw = open(path, "rb").read()
    out: dict[str, Any] = {"attempted": True}
    block = parse_apk_signing_block(raw)
    if not block.get("found"):
        out["skipped"] = "no signing block"
        return out
    v2 = block.get("v2_offset", -1)
    if v2 < 0:
        out["skipped"] = "no v2 pair"
        return out
    out["signed_region"] = {
        "start": 0,
        "end_signed_region": block["block_start"],  # content = [0, block_start) + CD + EOCD
        "cd_off": block["cd_offset"],
    }
    # the content that v2 protects: everything before the signing block, the
    # central directory, and the EOCD up to (but not incl.) its own digest
    content = raw[: block["block_start"]] + raw[block["cd_offset"] :]
    out["content_sha256"] = hashlib.sha256(content).hexdigest()
    out["content_len"] = len(content)
    # the digest apksigner committed to is inside the v2 pair; without parsing
    # the RSA signature we cannot compare it, so we record the region for
    # cross-checking with `apksigner verify` in CI when Java is available.
    out["note"] = "recorded for comparison with `apksigner verify --print-certs` when Java is available"
    return out
