#!/usr/bin/env python3
"""Fold authoritative vendor tool output into the engine's report.

The engine judges; the vendor tools corroborate. This script appends a
cross-check section and, where the two disagree, says so explicitly instead of
letting a wrong engine claim stand unqualified. It is deliberately tolerant:
every input file is optional because CI tool availability varies.
"""

from __future__ import annotations

import argparse
import os
import re
import sys


def read(p: str) -> str:
    if not p or not os.path.exists(p):
        return ""
    try:
        return open(p, encoding="utf-8", errors="replace").read()
    except OSError:
        return ""


def parse_apksigner(txt: str) -> dict[str, str]:
    out: dict[str, str] = {}
    if not txt.strip():
        return out
    if "Verifies" in txt:
        out["verified"] = "yes" if re.search(r"^\s*Verifies", txt, re.M) else "no"
    if "DOES NOT VERIFY" in txt:
        out["verified"] = "no"
    m = re.search(r"Signer #1 certificate DN:\s*(.+)", txt)
    if m:
        out["dn"] = m.group(1).strip()
    for key, rx in (
        ("sha256", r"certificate SHA-256 digest:\s*([0-9a-f:]+)"),
        ("sha1", r"certificate SHA-1 digest:\s*([0-9a-f:]+)"),
        ("md5", r"certificate MD5 digest:\s*([0-9a-f:]+)"),
    ):
        m = re.search(rx, txt, re.I)
        if m:
            out[key] = m.group(1).strip()
    schemes = []
    for line in txt.splitlines():
        m = re.match(r"^\s*Verified using (v[0-9.]+) scheme \(([^)]*)\):\s*(\w+)", line)
        if m:
            schemes.append(f"{m.group(1)} ({m.group(2)})|{m.group(3)}")
    if schemes:
        out["schemes"] = "\n".join(schemes)
    m = re.search(r"Number of signers:\s*(\d+)", txt)
    if m:
        out["signers"] = m.group(1)
    m = re.search(r"Signer #1 key algorithm:\s*(.+)", txt)
    if m:
        out["key_alg"] = m.group(1).strip()
    m = re.search(r"Signer #1 key size \(bits\):\s*(\d+)", txt)
    if m:
        out["key_bits"] = m.group(1)
    return out


def parse_zipalign(txt: str) -> str:
    if not txt.strip():
        return "not run"
    if "PASS." in txt:
        return "PASS - all relevant entries aligned"
    if "FAIL." in txt:
        return "FAIL - misaligned entries present"
    return txt.strip().splitlines()[-1][:120]


def parse_badging(txt: str) -> dict[str, str]:
    out: dict[str, str] = {}
    m = re.search(r"package: name='([^']*)' versionCode='([^']*)' versionName='([^']*)'", txt)
    if m:
        out["package"], out["versionCode"], out["versionName"] = m.groups()
    m = re.search(r"sdkVersion:'(\d+)'.*targetSdkVersion:'(\d+)'", txt, re.S)
    if m:
        out["minSdk"], out["targetSdk"] = m.groups()
    if "application-debuggable" in txt:
        out["debuggable"] = "yes"
    if "uses-implied-permission" in txt:
        out["implied_permissions"] = str(txt.count("uses-implied-permission"))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True)
    ap.add_argument("--apksigner", default="")
    ap.add_argument("--zipalign", default="")
    ap.add_argument("--aapt2", default="")
    ap.add_argument("--hashes", default="")
    a = ap.parse_args()

    if not os.path.exists(a.report):
        print(f"no report at {a.report}", file=sys.stderr)
        return 0

    sig = parse_apksigner(read(a.apksigner))
    za = parse_zipalign(read(a.zipalign))
    badge = parse_badging(read(a.aapt2))

    L: list[str] = ["", "---", "", "## Appendix B — vendor tool cross-check", ""]
    L.append("_These outputs come from Google's own build-tools, not from this repo's engine. "
             "They are the authority on signature validity and alignment._")
    L.append("")
    L.append("| check | result |")
    L.append("|---|---|")
    if sig:
        L.append(f"| apksigner verdict | **{sig.get('verified','unknown')}** |")
        if sig.get("dn"):
            L.append(f"| signer DN (vendor) | `{sig['dn']}` |")
        if sig.get("sha256"):
            L.append(f"| cert SHA-256 (vendor) | `{sig['sha256']}` |")
        for row in (sig.get("schemes") or "").splitlines():
            if "|" in row:
                k, v = row.split("|", 1)
                L.append(f"| apksigner {k.strip()} | {v.strip()} |")
        if sig.get("signers"):
            L.append(f"| number of signers | {sig['signers']} |")
        if sig.get("key_alg"):
            L.append(f"| signer key | {sig['key_alg']} {sig.get('key_bits','')} bits |")
    else:
        L.append("| apksigner verdict | unavailable on this runner |")
    L.append(f"| zipalign | {za} |")
    for k in ("package", "versionCode", "versionName", "minSdk", "targetSdk", "debuggable"):
        if k in badge:
            L.append(f"| aapt2 badging: {k} | `{badge[k]}` |")

    # explicit disagreement detection -> that is the part a human should read first
    eng = read(a.report)
    notes: list[str] = []
    if sig.get("verified") == "no":
        notes.append(
            "**apksigner says the package does NOT verify.** The engine can only report the "
            "presence of a signing block; the vendor verdict is decisive: this file was modified "
            "after it was signed."
        )
    if sig.get("verified") == "yes" and "Non-canonical APK Signing Block layout" in eng:
        notes.append(
            "The engine flagged a non-canonical signing-block layout, but apksigner *accepts* the "
            "package. Read that as: the block was written by a non-apksigner implementation that "
            "still produces a verifiable structure - i.e. evidence about the **tooling used to "
            "repackage** this build, not evidence that the signature is broken."
        )
    if "Package appears UNSIGNED" in eng and sig.get("verified"):
        notes.append("Engine 'UNSIGNED' finding is superseded by the vendor verdict.")
    if notes:
        L += ["", "### Where the two disagree", ""]
        for n in notes:
            L.append(f"- {n}")
    if a.hashes and os.path.exists(a.hashes):
        L += ["", "### Sample identity", "", read(a.hashes).strip()]
    L.append("")

    with open(a.report, "a", encoding="utf-8") as fh:
        fh.write("\n".join(L))
    print("cross-check appended to", a.report, file=sys.stderr)
    if sig.get("dn"):
        print("signer DN:", sig["dn"], file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
