#!/usr/bin/env python3
"""apk-audit — deep static analysis of an Android package, CI-friendly.

    python3 -m apk_audit <apk> [-o outdir] [--extract DIR] [--no-dex]

Layers (each optional and each degrading independently):
    container   zip/APK structure, alignment, signing block, repack traces
    signing     X.509 signer identity, key strength, debug-key detection
    manifest    permissions, exported surface, backup/flags, capability inference
    resources   resources.arsc string pool, UI wording, asset inventory
    native      ELF hardening, imports, JNI surface, anti-analysis strings
    dex         instruction-level behavioural evidence
Outputs: report.md, findings.json, audit.sarif, summary.md (CI job summary)
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import warnings
import zipfile

warnings.filterwarnings("ignore")
# androguard's loguru output would bury the report; silence it unless DEBUG
try:
    from loguru import logger as _lg

    _lg.remove()
    if os.environ.get("AUDIT_DEBUG"):
        _lg.add(sys.stderr, level="DEBUG")
except Exception:
    pass

from . import container, dex as dexmod, manifest, native, report, resources, signing
from .core import Findings, dump_json, file_hashes, human


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="apk-audit", description="Static audit of an APK")
    ap.add_argument("apk")
    ap.add_argument("-o", "--outdir", default="audit-out")
    ap.add_argument("--extract", default=None, help="where to unpack (default: <outdir>/unpacked)")
    ap.add_argument("--no-dex", action="store_true", help="skip the (slowest) DEX layer")
    ap.add_argument("--fail-on", default="CRITICAL", help="exit non-zero at/above this severity")
    args = ap.parse_args(argv)

    t0 = time.time()
    apk = os.path.abspath(args.apk)
    if not os.path.exists(apk):
        print(f"error: {apk} not found", file=sys.stderr)
        return 2
    os.makedirs(args.outdir, exist_ok=True)
    xdir = args.extract or os.path.join(args.outdir, "unpacked")
    os.makedirs(xdir, exist_ok=True)
    if not os.path.exists(os.path.join(xdir, "AndroidManifest.xml")):
        with zipfile.ZipFile(apk) as zf:
            zf.extractall(xdir)
        print(f"[*] unpacked {len(os.listdir(xdir))} top-level entries -> {xdir}", file=sys.stderr)

    F = Findings()
    h = file_hashes(apk)
    meta = {
        "apk": apk,
        "size": int(h["size"]),
        "size_h": human(int(h["size"])),
        "md5": h["md5"],
        "sha1": h["sha1"],
        "sha256": h["sha256"],
        "engine": "apk-audit 1.0",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "analysis": "static-only (sample never executed)",
    }

    layers: dict[str, dict] = {}

    def step(label: str, fn, *a, **kw):
        t = time.time()
        try:
            r = fn(*a, **kw)
            print(f"[*] {label:<12} ok   {time.time()-t:5.1f}s", file=sys.stderr)
            return r
        except Exception as e:  # keep the pipeline alive per-layer
            import traceback

            print(f"[!] {label:<12} FAIL {e!r}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            layers[f"{label}_error"] = {"error": repr(e)}
            return {}

    layers["container"] = step("container", container.analyse, apk, F)
    layers["signing"] = step("signing", signing.analyse, apk, F)
    mpath = os.path.join(xdir, "AndroidManifest.xml")
    layers["manifest"] = step("manifest", manifest.analyse, mpath, F) if os.path.exists(mpath) else {}
    layers["resources"] = step("resources", resources.analyse, xdir, F)
    layers["native"] = step("native", native.analyse, os.path.join(xdir, "lib"), F)
    if not args.no_dex:
        dexes = sorted(
            os.path.join(xdir, n)
            for n in os.listdir(xdir)
            if n.endswith(".dex")
        )
        layers["dex"] = step("dex", dexmod.analyse, dexes, F) if dexes else {}

    # merge identity into meta
    mf = layers.get("manifest", {})
    meta.update(
        {
            "package": mf.get("package"),
            "version_name": mf.get("version_name"),
            "version_code": mf.get("version_code"),
            "min_sdk": mf.get("min_sdk"),
            "target_sdk": mf.get("target_sdk"),
            "permissions": mf.get("permissions"),
            "components": len(mf.get("components", [])),
            "exported": mf.get("exported_count"),
            "signer": layers.get("signing", {}).get("primary_subject"),
            "signer_sha256": (layers.get("signing", {}).get("certificates") or [{}])[0].get("fingerprint_sha256"),
            "schemes": (layers.get("container", {}).get("signing_block") or {}).get("schemes"),
        }
    )
    dump_json(os.path.join(args.outdir, "layers.json"), layers)
    paths = report.write(args.outdir, F, meta, layers)

    print(f"\n=== {len(F)} findings, risk {F.score()[0]}/100 {F.score()[1]} in {time.time()-t0:.1f}s ===")
    for sev in (report.ORDER):
        n = len([f for f in F.items if f.severity is sev])
        if n:
            print(f"  {sev.emoji} {sev.name:<9} {n}")
    for k, v in paths.items():
        print(f"  -> {k}: {v}")

    from .core import Sev

    floor = getattr(Sev, args.fail_on.upper(), None)
    if floor is not None and any(f.severity >= floor for f in F.items):
        print(f"[x] findings at/above {floor.name} present -> non-zero exit", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
