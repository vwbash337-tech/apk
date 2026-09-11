"""Layer 5: AndroidManifest semantic audit.

Decodes the binary AXML and evaluates the manifest the way a Play policy
reviewer and a malware analyst both would: not "is INTERNET requested" but
"what does this combination of components + permissions + flags make
possible, and does the declared surface match the code we found".
"""

from __future__ import annotations

import re
from typing import Any
from xml.etree import ElementTree as ET

from .core import Finding, Findings, Sev

A = "{http://schemas.android.com/apk/res/android}"

PERM_RISK: dict[str, tuple[Sev, str]] = {
    "android.permission.INTERNET": (Sev.INFO, "Outbound network; needed by any connected app."),
    "android.permission.ACCESS_NETWORK_STATE": (Sev.INFO, "Connectivity probing."),
    "android.permission.WAKE_LOCK": (Sev.LOW, "Keeps CPU awake - required for a background loop that must survive doze."),
    "android.permission.FOREGROUND_SERVICE": (Sev.LOW, "Required to run a persistent visible service."),
    "android.permission.FOREGROUND_SERVICE_SPECIAL_USE": (Sev.MEDIUM,
        "'specialUse' is the escape-hatch foreground type: Play requires a written justification "
        "for it, and it is what services that would be rejected under a normal type use."),
    "android.permission.POST_NOTIFICATIONS": (Sev.LOW, "User-visible notifications (API 33+)."),
    "com.google.android.c2dm.permission.RECEIVE": (Sev.INFO, "Firebase Cloud Messaging delivery."),
    "android.permission.RECEIVE_SMS": (Sev.CRITICAL, "Reads SMS: intercepts 2FA one-time codes."),
    "android.permission.SEND_SMS": (Sev.CRITICAL, "Sends SMS: premium-rate fraud and silent OTP exfil."),
    "android.permission.READ_SMS": (Sev.CRITICAL, "Full SMS store read."),
    "android.permission.READ_CONTACTS": (Sev.HIGH, "Address-book harvesting."),
    "android.permission.CAMERA": (Sev.HIGH, "Image capture, possible silent photo."),
    "android.permission.RECORD_AUDIO": (Sev.HIGH, "Microphone capture."),
    "android.permission.ACCESS_FINE_LOCATION": (Sev.HIGH, "Precise geolocation."),
    "android.permission.READ_PHONE_STATE": (Sev.HIGH, "IMEI/IMSI/phone number lineage."),
    "android.permission.READ_EXTERNAL_STORAGE": (Sev.MEDIUM, "User file read."),
    "android.permission.WRITE_EXTERNAL_STORAGE": (Sev.MEDIUM, "Writes into shared storage."),
    "android.permission.QUERY_ALL_PACKAGES": (Sev.HIGH, "Full installed-app inventory (Play restricts this)."),
    "android.permission.REQUEST_INSTALL_PACKAGES": (Sev.CRITICAL, "Installs other APKs: dropper capability."),
    "android.permission.SYSTEM_ALERT_WINDOW": (Sev.CRITICAL, "Overlay attacks; tap-hijacking vector."),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (Sev.CRITICAL, "Reads/injects UI across apps."),
    "android.permission.PACKAGE_USAGE_STATS": (Sev.HIGH, "Usage surveillance."),
    "android.permission.GET_ACCOUNTS": (Sev.HIGH, "Device account enumeration."),
    "android.permission.READ_CALL_LOG": (Sev.CRITICAL, "Call history."),
    "android.permission.PROCESS_OUTGOING_CALLS": (Sev.CRITICAL, "Call redirection."),
    "android.permission.RECEIVE_BOOT_COMPLETED": (Sev.MEDIUM, "Boot persistence."),
}

# components whose name implies capability
COMPONENT_MEANING: list[tuple[str, str]] = [
    (r"WebView", "Embeds a remote-controlled browser surface"),
    (r"TwoFactor|2fa|Otp", "Handles a second-factor code - i.e. the app sees the 2FA token"),
    (r"InstagramLogin|SocialLogin|PasswordLogin", "Collects platform credentials directly"),
    (r"Request(Like|Comment|Save|Repost|Follow)", "Automation of engagement actions"),
    (r"Coin|Miner|Reward|Coupon|Invite|Upgrade|LeaderBoard", "Gamified incentive economy (referral/engagement farming)"),
    (r"DoTasks|TaskAction|Worker|Job|Service$", "Persistent background task loop"),
    (r"Orders", "Order queue - engagement sold or traded in bulk"),
]


def analyse(manifest_path: str, F: Findings) -> dict[str, Any]:
    info: dict[str, Any] = {}
    xml = open(manifest_path, "rb").read()
    if xml[:4] == b"\x03\x00\x08\x00" or xml[:2] == b"\x03\x00":
        xml = _decode_axml(manifest_path)
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        F.add(Finding("MAN-000", "AndroidManifest.xml failed to parse", Sev.HIGH, "manifest",
                      f"{e}. A manifest that cannot be parsed by standard tooling is itself a "
                      f"finding: it means the file was hand-edited after build or is deliberately "
                      f"malformed to skip scanners.", [repr(e)]))
        return info
    return _eval(root, F, info, xml)


def _decode_axml(path: str) -> bytes:
    """Binary AXML -> text XML. Uses androguard when present."""
    from androguard.core.axml import AXMLPrinter
    from lxml import etree

    p = AXMLPrinter(open(path, "rb").read())
    return etree.tostring(p.get_xml_obj(), pretty_print=True)



def _eval(root: ET.Element, F: Findings, info: dict[str, Any], raw: bytes) -> dict[str, Any]:
    pkg = root.get("package", "?")
    info["package"] = pkg
    info["version_code"] = root.get(f"{A}versionCode")
    info["version_name"] = root.get(f"{A}versionName")
    info["install_location"] = root.get(f"{A}installLocation")

    sdk = root.find("uses-sdk")
    if sdk is not None:
        info["min_sdk"] = sdk.get(f"{A}minSdkVersion")
        info["target_sdk"] = sdk.get(f"{A}targetSdkVersion")
        info["max_sdk"] = sdk.get(f"{A}maxSdkVersion")
        try:
            ts = int(info["target_sdk"] or 0)
            if ts and ts < 33:
                F.add(
                    Finding(
                        "MAN-001",
                        f"targetSdkVersion {ts} is below current platform policy",
                        Sev.MEDIUM,
                        "manifest",
                        "Low target SDK keeps runtime-permission and background-execution "
                        "restrictions weaker than they are for modern apps - deliberately choosing "
                        "an old target is a way to keep grabbing data without prompting.",
                        [f"targetSdk={ts}", f"minSdk={info.get('min_sdk')}"],
                    )
                )
        except ValueError:
            pass
        if info.get("max_sdk"):
            F.add(
                Finding("MAN-002", "maxSdkVersion set", Sev.MEDIUM, "manifest",
                        "Caps installable Android versions - used to stay off newer, better-instrumented OS releases.",
                        [info["max_sdk"]])
            )

    # ---------------- permissions ----------------
    perms = [p.get(f"{A}name") for p in root.findall("uses-permission") if p.get(f"{A}name")]
    declared = [p.get(f"{A}name") for p in root.findall("permission") if p.get(f"{A}name")]
    info["permissions"] = perms
    info["custom_permissions"] = declared
    risky = []
    for p in perms:
        risk, why = PERM_RISK.get(p, (Sev.LOW, "No curated assessment for this permission."))
        if risk >= Sev.MEDIUM:
            risky.append((p, risk, why))
    for p, risk, why in risky:
        F.add(
            Finding(
                "PERM:" + p.split(".")[-1],
                f"Permission {p}",
                risk,
                "manifest",
                why,
                [p],
                attack=["D4.001 - User data / privacy"],
            )
        )
    for p in declared:
        node = root.find(f"permission[@{A}name='{p}']")
        lvl = node.get(f"{A}protectionLevel") if node is not None else None
        if lvl in ("signature", "privileged"):
            continue
        F.add(
            Finding(
                "PERM-DEF:" + p.split(".")[-1],
                f"App defines its own permission {p} (level {lvl})",
                Sev.INFO,
                "manifest",
                "Self-defined permissions set the boundary for other apps talking to this app's "
                "components. 'signatureOrOpen'/normal levels mean another app can hold them.",
                [f"{p} protectionLevel={lvl}"],
            )
        )

    # ---------------- application flags ----------------
    app = root.find("application")
    flags: dict[str, Any] = {}
    if app is not None:
        for k in ("debuggable", "allowBackup", "usesCleartextTraffic", "networkSecurityConfig",
                  "extractNativeLibs", "testOnly", "vmSafeMode", "hasCode", "splitsAllowed",
                  "zygotePreloadName", "appComponentFactory", "preserveLegacyExternalStorage",
                  "requestLegacyExternalStorage", "allowNativeHeapPointerTagging", "dataExtractionRules",
                  "fullBackupContent", "supportsRtl", "hardwareAccelerated", "crossProfile",
                  "multiArch", "allowAudioPlaybackCapture", "enableOnBackInvokedCallback"):
            v = app.get(A + k)
            if v is not None:
                flags[k] = v
        info["application_flags"] = flags
        if flags.get("debuggable") == "true":
            F.add(
                Finding("MAN-010", "android:debuggable=true", Sev.CRITICAL, "manifest",
                        "Run-as, JDWP attach and full heap inspection are possible for anyone who can "
                        "install it; a released sample with this flag leaks its runtime secrets.",
                        ["debuggable=true"], cwe="CWE-919")
            )
        if flags.get("testOnly") == "true":
            F.add(Finding("MAN-011", "android:testOnly=true", Sev.HIGH, "manifest",
                          "Build was never meant to ship; only installs with -t."))
        if flags.get("allowBackup") == "true" and not flags.get("fullBackupContent"):
            F.add(
                Finding("MAN-012", "allowBackup=true with no backup rules", Sev.HIGH, "manifest",
                        "adb backup / cloud backup can exfiltrate the app's private data directory, "
                        "including any stored session or credential, with no user-visible prompt on "
                        "many OEM builds.",
                        ["allowBackup=true", f"fullBackupContent={flags.get('fullBackupContent')}",
                         f"dataExtractionRules={flags.get('dataExtractionRules')}"],
                        cwe="CWE-530", attack=["D4.001 - Data at rest"])
            )
        elif flags.get("allowBackup") == "true":
            F.add(
                Finding("MAN-013", "allowBackup=true (rules present)", Sev.MEDIUM, "manifest",
                        "Backup is enabled; the referenced rules only carve out what is excluded, so "
                        "anything not listed is still exportable via adb backup on Android <12.",
                        [f"fullBackupContent={flags.get('fullBackupContent')}",
                         f"dataExtractionRules={flags.get('dataExtractionRules')}"],
                        cwe="CWE-530")
            )
        if flags.get("usesCleartextTraffic") == "true":
            F.add(Finding("MAN-014", "Cleartext traffic allowed", Sev.HIGH, "manifest",
                          "http:// endpoints permitted -> credentials cross the wire unencrypted.",
                          ["usesCleartextTraffic=true"], cwe="CWE-319"))
        if not flags.get("networkSecurityConfig"):
            F.add(
                Finding("MAN-015", "No network_security_config declared", Sev.MEDIUM, "manifest",
                        "No pinning / trust-anchor restriction is configured at the platform level, so "
                        "any pinning that exists has to be implemented (and bypassed) in code.",
                        ["networkSecurityConfig absent"])
            )
        if flags.get("extractNativeLibs") == "true":
            F.add(Finding("MAN-016", "extractNativeLibs=true", Sev.MEDIUM, "manifest",
                          "Native code is unpacked to /data/app where it can be swapped by tooling on a "
                          "rooted device before load.", ["extractNativeLibs=true"]))
        info["app_class"] = app.get(A + "name")
        info["app_label_ref"] = app.get(A + "label")

    # ---------------- components ----------------
    comps: list[dict[str, Any]] = []
    for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for c in (root.findall(f"application/{tag}") + root.findall(tag)):
            name = c.get(A + "name", "?")
            exported = c.get(A + "exported")
            if exported is None:
                exported = "true" if c.find("intent-filter") is not None else "false"
            rec = {
                "type": tag,
                "name": name,
                "exported": exported == "true",
                "permission": c.get(A + "permission"),
                "process": c.get(A + "process"),
                "foregroundServiceType": c.get(A + "foregroundServiceType"),
                "authorities": c.get(A + "authorities"),
                "grantUriPermissions": c.get(A + "grantUriPermissions") == "true",
                "taskAffinity": c.get(A + "taskAffinity"),
                "filters": [],
            }
            for f in c.findall("intent-filter"):
                flt = {
                    "actions": [a.get(A + "name", "?") for a in f.findall("action")],
                    "categories": [x.get(A + "name", "?") for x in f.findall("category")],
                    "data": [
                        {k.split("}")[-1]: v for k, v in x.attrib.items()} for x in f.findall("data")
                    ],
                }
                rec["filters"].append(flt)
            comps.append(rec)
    info["components"] = comps

    # exported analysis
    exposed = [c for c in comps if c["exported"]]
    info["exported_count"] = len(exposed)
    for c in exposed:
        if c["permission"]:
            continue
        if c["type"] == "provider" and c["grantUriPermissions"]:
            F.add(Finding("EXP-001", f"ContentProvider {c['name']} exported with URI grants", Sev.HIGH,
                          "attack-surface", "Other apps may read URIs this provider serves.",
                          [f"authorities={c['authorities']}"], cwe="CWE-925"))
        for f in c["filters"]:
            for a in f["actions"]:
                if a not in ("android.intent.action.MAIN", "android.intent.action.VIEW",
                             "android.intent.action.SEND", "android.intent.action.SENDTO") and "firebase" not in a and "c2dm" not in a:
                    F.add(Finding("EXP-002", f"Exported {c['type']} {c['name']} responds to {a}", Sev.MEDIUM,
                                  "attack-surface", "Custom exported action = an IPC entry point any app on the "
                                  "device can drive; look for missing input validation here.", [f"permission={c['permission']}"]))
    # implicit-intent hijack: SEND with no category default
    # foreground service types
    for c in comps:
        if c["type"] == "service" and c["foregroundServiceType"]:
            F.add(Finding("FGS-001", f"Foreground service {c['name']} type={c['foregroundServiceType']}", Sev.MEDIUM,
                          "persistence",
                          "specialUse (0x40000000) foreground services are the loophole for long-lived "
                          "work that would otherwise be killed; here it is the engagement loop that keeps "
                          "liking/following while the app is backgrounded.",
                          [f"type={c['foregroundServiceType']}", f"exported={c['exported']}"],
                          attack=["D4.003 - Persistence"]))
    # receivers with no intent-filter that the code registers dynamically
    for c in comps:
        if c["type"] == "receiver" and not c["filters"] and not c["permission"]:
            F.add(Finding("RCV-001", f"Bare receiver {c['name']}", Sev.LOW, "attack-surface",
                          "Declared with no filter and no permission; commands to it can come from "
                          "runtime-registered filters, so check what actions it accepts."))

    # ---------------- feature inference from names ----------------
    names = [c["name"] for c in comps]
    inferred: dict[str, list[str]] = {}
    for rx, why in COMPONENT_MEANING:
        hits = [n for n in names if re.search(rx, n, re.I)]
        if hits:
            inferred[why] = hits
    info["inferred_features"] = inferred
    if any("2FA" in why or "2fa" in why.lower() for why in inferred):
        pass
    for why, hits in inferred.items():
        sev = Sev.HIGH if "credentials" in why or "second-factor" in why else Sev.MEDIUM if "automation" in why else Sev.LOW
        F.add(Finding("FEAT:" + why[:24], "Component evidence: " + why, sev, "capability",
                      "Derived from component names only, i.e. from what the developer chose to "
                      "announce. Each name below is a class you can pull apart directly.",
                      hits[:10]))

    # deep links / schemes
    schemes = sorted({
        d.get("scheme", "")
        for c in comps
        for f in c["filters"]
        for d in f["data"]
        if d.get("scheme")
    })
    info["url_schemes"] = schemes
    hosts_dl = sorted({
        d.get("host", "")
        for c in comps
        for f in c["filters"]
        for d in f["data"]
        if d.get("host")
    })
    info["deeplink_hosts"] = hosts_dl
    if schemes:
        F.add(Finding("EXP-010", f"Custom URL schemes: {', '.join(schemes)}", Sev.MEDIUM, "attack-surface",
                      "Any app (or webpage with user interaction) can launch this app with attacker "
                      "parameters via these schemes. Verify that every parameter arriving this way is "
                      "re-validated.", [", ".join(schemes), "hosts: " + ", ".join(hosts_dl)]))
    return info
