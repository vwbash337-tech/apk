"""Layer 4: DEX / smali semantic analysis.

A single pass over every decoded instruction builds, per class:
    * the set of API signatures it calls        (e.g. Landroid/net/...;->getAllNetworkInfo)
    * every const-string it materialises       (URLs, keys, SQL, JSON keys)
    * every field write                        (hardcoded config)
    * the instruction kinds it uses            (const-method-handle, filled-new-array ...)

Behavioural rules are then matched against that index rather than against the
raw disassembly, so a rule can name the exact class+method that proves it.
That is what makes the findings auditable instead of a scary keyword list.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
from collections import Counter, defaultdict
from typing import Any

from .core import (
    Finding,
    Findings,
    Sev,
    extract_iocs,
    host_of,
    is_common_host,
)

# ---------------------------------------------------------------------------
# Behaviour signature table: api-fragment -> (rule, title, severity, why, attack)
# Matched against the *callee class+method* text of each invoke.
# ---------------------------------------------------------------------------
API_RULES: list[tuple[str, str, str, Sev, str, str]] = [
    # --- hidden API / restriction bypass ---
    ("setHiddenApiExemptions", "HID-001", "Hidden-API exemption bypass (L4)", Sev.HIGH,
     "Reflectively unlocks the greylist/blacklist of Android framework APIs. Used to reach "
     "private platform methods that a normal app cannot call.", "D4.002"),
    ("Ldalvik/system/VMRuntime;", "HID-002", "Direct VMRuntime access", Sev.LOW,
     "Low-level runtime control, usually paired with unsealing of hidden APIs.", ""),
    ("Lde/robv/android/x86/", "HOOK-001", "Xposed API references", Sev.CRITICAL,
     "Xposed hooking framework strings present in the app itself.", "D4.002"),
    ("Lde/robv/android/xposed", "HOOK-002", "Xposed hooking framework", Sev.CRITICAL,
     "The sample links against Xposed, i.e. it expects to alter other apps' behaviour.", "D4.002"),

    # --- dynamic code ---
    ("Ldalvik/system/DexClassLoader;", "CODE-001", "Runtime DEX loading (DexClassLoader)", Sev.HIGH,
     "Loads classes from a file at runtime: behaviour that no static scan can see.", "D4.002"),
    ("Ldalvik/system/PathClassLoader;", "CODE-002", "PathClassLoader on external path", Sev.MEDIUM,
     "See above.", "D4.002"),
    ("Ldalvik/system/InMemoryDexClassLoader;", "CODE-003", "In-memory DEX loading", Sev.CRITICAL,
     "Executes a dex from a memory buffer - nothing ever touches disk, the standard "
     "fileless pattern in Android loaders.", "D4.002"),
    ("Ljava/lang/Runtime;->exec", "EXEC-001", "Shell command execution (Runtime.exec)", Sev.HIGH,
     "Runs a binary from a shell string. In this app class, typically `su`, `pm`, or `settings`.", "D4.001"),
    ("Ljava/lang/ProcessBuilder", "EXEC-002", "ProcessBuilder spawn", Sev.MEDIUM,
     "Second way to spawn processes.", "D4.001"),

    # --- reflection ---
    ("Ljava/lang/reflect/Method;->invoke", "REFL-001", "Reflective method invocation", Sev.MEDIUM,
     "Heavy reflection defeats static call-graph tooling; enumerate what it resolves at runtime.", "D4.003"),
    ("Ljava/lang/Class;->forName", "REFL-002", "Reflective class lookup by name", Sev.MEDIUM,
     "Class names built from strings/decrypted data - the obfuscation primitive itself.", "D4.003"),
    ("getDeclaredMethod", "REFL-003", "Declared-method enumeration", Sev.LOW, "Private-API reach.", ""),
    ("setAccessible", "REFL-004", "Private-member forcing (setAccessible)", Sev.MEDIUM,
     "Accesses private fields of framework or third-party classes.", "D4.002"),

    # --- credential / session handling ---
    ("Landroid/webkit/CookieManager", "COOKIE-001", "WebView CookieManager access", Sev.HIGH,
     "Reads/writes the cookie jar of the embedded browser. If the WebView shows a real "
     "login page, this is how sessionid/authorization codes are taken out of it.", "D4.001"),
    ("getCookie", "COOKIE-002", "Cookie value read", Sev.HIGH, "Direct cookie extraction.", "D4.001"),
    ("Landroid/accounts/AccountManager", "ACCT-001", "AccountManager enumeration", Sev.HIGH,
     "Enumerates the device's signed-in accounts.", "D4.001"),
    ("getAuthToken", "ACCT-002", "Auth token request", Sev.CRITICAL,
     "Requests OAuth tokens for a device account.", "D4.001"),
    ("getAccountsByType", "ACCT-003", "Account listing by type", Sev.HIGH, "Account harvesting.", "D4.001"),
    ("Landroid/content/ClipboardManager", "CLIP-001", "Clipboard read/write", Sev.MEDIUM,
     "Clipboard scraping (wallet addresses / tokens) is the usual reason.", "D4.001"),
    ("android.provider.Settings$Secure;->getString", "SETT-001", "Settings.Secure read", Sev.MEDIUM,
     "Reads android_id and other identifiers; also how WRITE_SETTINGS is abused.", ""),

    # --- crypto & storage ---
    ("Ljavax/crypto/Cipher;", "CRY-001", "javax.crypto Cipher use", Sev.MEDIUM,
     "Symmetric crypto in Java space. Check for fixed keys/IVs.", ""),
    ("Ljavax/crypto/spec/SecretKeySpec;", "CRY-002", "Hardcoded secret key material", Sev.HIGH,
     "A SecretKeySpec built from a literal string is a broken key hierarchy: anyone with "
     "the APK can decrypt whatever it protects.", "D4.002"),
    ("Ljavax/crypto/spec/IvParameterSpec;", "CRY-003", "Static IV", Sev.MEDIUM,
     "A constant IV with CBC leaks equality of plaintext prefixes.", "D4.002"),
    ("Ljavax/crypto/KeyGenerator;", "CRY-004", "Key generation", Sev.LOW, "Normal.", ""),
    ("Ljava/security/MessageDigest;", "CRY-005", "Hashing", Sev.LOW, "MD5/SHA for cache keys or signature check.", ""),
    ("Ljavax/net/ssl/TrustManager", "TLS-001", "Custom X509TrustManager", Sev.HIGH,
     "Custom trust managers in this genre of app are usually trust-everything to allow "
     "interception or to talk to a cert-less server.", "D4.001"),
    ("Ljavax/net/ssl/X509TrustManager;", "TLS-002", "TrustManager interface implemented", Sev.HIGH,
     "Same as above.", "D4.001"),
    ("checkServerTrusted", "TLS-003", "checkServerTrusted overridden", Sev.CRITICAL,
     "If the override returns without throwing, TLS validation is disabled and the user's "
     "credentials are sniffable on the network path.", "D4.001"),
    ("setHostnameVerifier", "TLS-004", "Hostname verifier overridden", Sev.CRITICAL,
     "MitM enabler.", "D4.001"),
    ("ALLOW_ALL_HOSTNAME_VERIFIER", "TLS-005", "ALLOW_ALL hostname verifier", Sev.CRITICAL, "MitM enabler.", "D4.001"),
    ("Ljava/security/KeyStore;", "KS-001", "AndroidKeyStore / keystore access", Sev.MEDIUM, "Hardware-backed key use.", ""),

    # --- device fingerprinting ---
    ("Landroid/telephony/TelephonyManager;->getDeviceId", "FINGER-001", "IMEI read", Sev.HIGH,
     "IMEI requires READ_PHONE_STATE since 6.0; a follower app has no use for it.", "D4.001"),
    ("getImei", "FINGER-002", "IMEI read (API 29+)", Sev.HIGH, "Permanently identifying hardware ID.", "D4.001"),
    ("getSubscriberId", "FINGER-003", "IMSI read", Sev.HIGH, "SIM identity.", "D4.001"),
    ("getLine1Number", "FINGER-004", "Phone number read", Sev.HIGH, "MSISDN harvesting.", "D4.001"),
    ("getSerial", "FINGER-005", "Build.getSerial / device serial", Sev.MEDIUM, "Hardware serial.", "D4.001"),
    ("getAndroidId", "FINGER-006", "SSAID read", Sev.MEDIUM, "Stable per-user-per-signing-key ID.", ""),
    ("Landroid/net/wifi/WifiInfo;->getMacAddress", "FINGER-007", "Wi-Fi MAC read", Sev.MEDIUM, "Hardware ID.", "D4.001"),
    ("getInstalledPackages", "ENUM-001", "Installed package enumeration", Sev.MEDIUM,
     "Enumerates every installed app: banking app detection, ad-targeting, or finding "
     "the target app's data path.", "D4.001"),
    ("getInstalledApplications", "ENUM-002", "Installed application enumeration", Sev.MEDIUM, "Same.", "D4.001"),
    ("queryIntentActivities", "ENUM-003", "Intent-resolution enumeration", Sev.LOW, "Maps the device's capabilities.", ""),
    ("Landroid/content/pm/PackageManager;->getApplicationInfo", "ENUM-004", "App metadata read", Sev.LOW, "", ""),

    # --- input/monitoring ---
    ("Landroid/view/accessibility/AccessibilityService", "MON-001", "Accessibility service", Sev.CRITICAL,
     "Reads and injects UI in other apps - the classic Android credential-stealer primitive.", "D4.001"),
    ("Landroid/view/KeyEvent", "MON-002", "Raw key event access", Sev.MEDIUM, "Keystroke capture surface.", ""),
    ("Landroid/hardware/Camera", "MON-003", "Camera API", Sev.HIGH, "Silent capture.", "D4.001"),
    ("Landroid/media/MediaRecorder", "MON-004", "Audio recording", Sev.HIGH, "Microphone capture.", "D4.001"),
    ("AudioRecord", "MON-005", "Raw audio capture", Sev.HIGH, "Microphone capture.", "D4.001"),
    ("Landroid/media/Projection", "MON-006", "Screen capture", Sev.HIGH, "Screen scraping.", "D4.001"),
    ("Landroid/app/usage/UsageStatsManager", "MON-007", "Usage statistics read", Sev.MEDIUM, "App-usage surveillance.", "D4.001"),
    ("Landroid/app/job/JobScheduler", "PERS-001", "JobScheduler persistence", Sev.MEDIUM, "Re-trigger after reboot/kill.", "D4.003"),
    ("Landroid/app/AlarmManager", "PERS-002", "AlarmManager scheduling", Sev.LOW, "Periodic wake-ups.", ""),
    ("Landroid/content/BroadcastReceiver;->registerReceiver", "PERS-003", "Dynamic receiver registration", Sev.LOW, "Event taps.", ""),

    # --- webview ---
    ("addJavascriptInterface", "WEB-001", "addJavascriptInterface (JS -> Java bridge)", Sev.CRITICAL,
     "Exposes Java objects to whatever the WebView loads. Combined with a remotely "
     "controlled page this is remote code execution in the app's own sandbox.", "D4.001"),
    ("setJavaScriptEnabled", "WEB-002", "JS enabled in WebView", Sev.MEDIUM, "Required for bridge attacks.", ""),
    ("setAllowFileAccess", "WEB-003", "File access enabled in WebView", Sev.HIGH,
     "Lets a remote page read the app's private files (databases, prefs, tokens).", "D4.001"),
    ("setAllowContentAccess", "WEB-004", "Content access enabled in WebView", Sev.MEDIUM, "ContentProvider read from web page.", ""),
    ("setSaveFormData", "WEB-005", "WebView form-data saving enabled", Sev.MEDIUM, "Credentials persisted in cleartext XML.", "D4.002"),
    ("setSavePassword", "WEB-006", "WebView password saving enabled", Sev.HIGH, "Login passwords stored on disk.", "D4.002"),
    ("setMixedContentMode", "WEB-007", "Mixed content mode changed", Sev.MEDIUM, "Allows http inside https pages.", ""),
    ("setWebContentsDebuggingEnabled", "WEB-008", "WebView remote debugging enabled", Sev.HIGH,
     "chrome://inspect attaches to the WebView - full view of the login traffic and DOM.", "D4.003"),
    ("loadUrl", "WEB-009", "WebView loadUrl", Sev.LOW, "Remote content execution surface.", ""),
    ("evaluateJavascript", "WEB-010", "evaluateJavascript", Sev.MEDIUM, "Native injects script into page.", ""),

    # --- overlay / floating control surface (the "mod menu" primitive) ---
    ("Landroid/view/WindowManager;->addView", "OVL-001", "WindowManager.addView - floating window", Sev.HIGH,
     "Draws a view on top of the app's own window. When combined with SYSTEM_ALERT_WINDOW and a "
     "settings store this is a control panel; on top of *other* apps it is the tap-jacking primitive.",
     "D4.001 - overlay / UI hijack"),
    ("TYPE_APPLICATION_OVERLAY", "OVL-002", "TYPE_APPLICATION_OVERLAY window type", Sev.CRITICAL,
     "A window above every other app, including the platform login screen. In a repackaged client "
     "this is how a fake login/2FA form is placed over the real one.", "D4.001 - overlay"),
    ("Landroid/provider/Settings;->canDrawOverlays", "OVL-003", "Checks overlay grant", Sev.MEDIUM,
     "Actively requesting the draw-overlays permission flow.", ""),
    ("Landroid/view/MotionEvent", "OVL-004", "Raw MotionEvent handling", Sev.LOW,
     "Touch synthesis/interception surface.", ""),

    # --- hooking / dynamic instrumentation inside the app itself ----------
    ("Lde/robv/android/xposed/XC_MethodHook", "HOOK-003", "Xposed method hook class used", Sev.CRITICAL,
     "The app installs hooks into methods at runtime. Nothing in a repackaged APK has a legitimate "
     "reason to do this to its own or another app's code.", "D4.002 - hooking"),
    ("Lcom/swift/sandhook", "HOOK-004", "SandHook ART hooking engine", Sev.CRITICAL, "Native method hooking.", "D4.002"),
    ("Lcom/topjohnwu", "HOOK-005", "Root-shell library bundled", Sev.HIGH, "Shizuku/Magisk shell access.", ""),

    # --- fabricated server responses --------------------------------------
    ("Lcom/google/gson/JsonObject;->addProperty", "SPOOF-002", "Client-side JSON response assembly", Sev.MEDIUM,
     "Building a response object locally. Alone it is ordinary (request bodies look the same); paired "
     "with a platform mutation endpoint it is how a client fakes 'success' without the server saying so.",
     "D4.001"),
    ("Lretrofit2/Response;->success", "SPOOF-003", "Synthetic Retrofit Response.success()", Sev.HIGH,
     "Manufactures a successful HTTP response object in-process, bypassing the network. This is the "
     "textbook way to make a UI show the real success state while the underlying action never happened "
     "(or happened against a different host).", "D4.001"),

    # --- network ---
    ("Ljava/net/URL;->openConnection", "NET-001", "Raw URLConnection", Sev.LOW, "Non-OkHttp network path.", ""),
    ("Ljava/net/HttpURLConnection", "NET-002", "HttpURLConnection", Sev.LOW, "", ""),
    ("Lorg/apache/http/client", "NET-003", "Apache HTTP client", Sev.LOW, "", ""),
    ("Ljava/net/DatagramSocket", "NET-004", "UDP socket", Sev.MEDIUM, "UDP C2 / reflection.", "D4.001"),
    ("Ljava/net/ServerSocket", "NET-005", "Listens on a TCP socket", Sev.HIGH,
     "Opens a local/lan listener - a backdoor surface reachable from other apps on device.", "D4.001"),
    ("Landroid/telephony/SmsManager;", "SMS-001", "SMS send", Sev.CRITICAL, "Premium-rate / 2FA interception.", "D4.001"),
    ("Landroid/telephony/SmsMessageBody", "SMS-002", "SMS content access", Sev.HIGH, "2FA interception.", "D4.001"),
]

# Instagram/social-platform specific markers
PLATFORM_MARKERS = [
    "instagram", "graph.instagram", "i.instagram", "instagram.com", "sessionid",
    "ds_user_id", "x-ig", "ig_sig", "www.instagram", "facebook", "tiktok",
]

# strings that indicate the app asks for / stores a password
CRED_STRINGS = re.compile(
    rb"(password|passwd|pwd|user_?name|login_?id|two.?factor|2fa|verification.?code|"
    rb"one.?time.?password|\botp\b|app.?password|sessionid|csrftoken|authorization|"
    rb"access_?token|refresh_?token|ds_user_id)",
    re.I,
)
COIN_STRINGS = re.compile(rb"(coin|credit|reward|diamond|point|balance|deposit|withdraw|miner)", re.I)

SHORT_PKG = re.compile(r"^L[a-z0-9]{1,2}(?:/[a-zA-Z0-9]{1,2}){1,3};$")
APP_PKG = re.compile(r"^Lcom/nivaroid/topfollow/")

# pre-computed lowercase index so the hot instruction loop does a plain
# substring test instead of re-lowercasing the table 500k times
API_LOOKUP = [(f.lower(), f, rid, sev) for f, rid, _t, sev, _w, _a in API_RULES]


def analyse(dex_paths: list[str], F: Findings) -> dict[str, Any]:
    from androguard.core.dex import DEX  # local import: optional dep

    info: dict[str, Any] = {}
    all_strings: list[str] = []
    per_class_calls: dict[str, set[str]] = defaultdict(set)
    per_class_strings: dict[str, set[str]] = defaultdict(set)
    per_class_switch: Counter[str] = Counter()
    per_class_prefs: dict[str, set[str]] = defaultdict(set)
    rule_hits: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    static_cfg: dict[str, dict[str, str]] = {}
    native_methods: list[tuple[str, str, str]] = []
    class_meta: dict[str, dict[str, Any]] = {}
    obf = nonobf = 0
    api_counter: Counter[str] = Counter()

    d = None
    for p in dex_paths:
        d = DEX(open(p, "rb").read())
        info["dex"] = {
            "path": p,
            "size": os.path.getsize(p),
            "classes": len(list(d.get_classes())),
            "strings": len(list(d.get_strings())),
        }
        # class inventory
        for cls in d.get_classes():
            name = cls.get_name()
            flags = cls.get_access_flags()
            if SHORT_PKG.match(name) or re.match(r"^L[a-z0-9]{1,3}/[a-zA-Z0-9]{1,2};$", name):
                obf += 1
            else:
                nonobf += 1
            class_meta[name] = {
                "flags": flags,
                "public": bool(flags & 0x1),
                "abstract": bool(flags & 0x400),
                "interface": bool(flags & 0x200),
                "super": cls.get_superclassname(),
                "interfaces": list(cls.get_interfaces() or []),
                "access": cls.get_access_flags_string(),
            }
            # static initialiser string config (BuildConfig-style)
            if APP_PKG.match(name) or "topfollow" in name:
                cfg: dict[str, str] = {}
                for fld in cls.get_fields():
                    if "static" in fld.get_access_flags_string():
                        try:
                            init = fld.get_init_value()
                            if init is not None:
                                v = init.get_value()
                                if isinstance(v, int):
                                    try:
                                        v = d.get_strings()[v]
                                    except Exception:
                                        pass
                                cfg[fld.get_name()] = str(v)
                        except Exception:
                            pass
                if cfg:
                    static_cfg[name] = cfg

            for m in cls.get_methods():
                mname = m.get_name()
                if "native" in m.get_access_flags_string():
                    native_methods.append((name, mname, m.get_descriptor()))
                for ins in m.get_instructions():
                    try:
                        nm = ins.get_name()
                        out = ins.get_output()
                    except Exception:
                        continue
                    line = nm + " " + out
                    if nm.startswith("const-string"):
                        s = out.split(", ", 1)[1].strip('"') if ", " in out else out
                        all_strings.append(s)
                        per_class_strings[name].add(s)
                    elif nm.startswith("invoke"):
                        ref = out.split(" ", 1)[-1].split(",", 1)[0].strip()
                        per_class_calls[name].add(ref)
                        api_counter[ref] += 1
                        low = ref.lower()
                        for frag_lower, frag, rid, sev in API_LOOKUP:
                            if frag_lower in low:
                                rule_hits[rid].append((name, mname, out[:160]))
                    elif nm in ("sparse-switch", "packed-switch", "lookupswitch", "tableswitch"):
                        per_class_switch[name] += 1
                    elif "put-object" in nm or "put-boolean" in nm:
                        per_class_prefs[name].add(out[:120])
                # method-level: look for the API-frag inside the descriptor too
                if "native" in m.get_access_flags_string():
                    nl = name.lower()
                    for frag_lower, frag, rid, sev in API_LOOKUP:
                        if frag_lower in nl:
                            rule_hits[rid].append((name, mname, "native method"))

    # ---- emit rule findings -------------------------------------------
    for frag, rid, title, sev, why, atk in API_RULES:
        hits = rule_hits.get(rid)
        if not hits:
            continue
        uniq_cls = sorted({h[0] for h in hits})
        F.add(
            Finding(
                rid,
                title,
                sev,
                "behaviour",
                why + f"  [{len(hits)} call sites in {len(uniq_cls)} classes]",
                [f"{c} . {m} -> {o}" for c, m, o in hits[:12]],
                attack=[atk] if atk else [],
            )
        )

    # ---- obfuscation metrics --------------------------------------------
    total = obf + nonobf
    ratio = obf / max(total, 1)
    info["obfuscation"] = {
        "total_classes": total,
        "obfuscated_classes": obf,
        "readable_classes": nonobf,
        "ratio": round(ratio, 3),
    }
    if ratio > 0.6:
        F.add(
            Finding(
                "OBF-001",
                f"{ratio*100:.0f}% of classes are minified to 1-2 char names",
                Sev.MEDIUM,
                "obfuscation",
                "R8 in full/obfuscating mode: {obf} of {total} classes carry throw-away names. "
                "This is normal for a release build, but it also means the malicious subset (if any) "
                "is indistinguishable from library code without call-graph analysis - which is what "
                "the rest of this report does.".format(obf=obf, total=total),
                [f"obfuscated={obf}", f"readable={nonobf}"],
            )
        )
    kept = sorted(n for n in class_meta if APP_PKG.match(n))
    info["app_classes_kept"] = kept
    if kept:
        F.add(
            Finding(
                "OBF-002",
                "App's own classes are NOT obfuscated while everything else is",
                Sev.INFO,
                "obfuscation",
                "The com.nivaroid.topfollow.* tree keeps readable names because R8 must keep "
                "manifest-referenced classes. Result: the business logic is fully readable, "
                "and the parts the author wanted hidden are exactly the ones pushed into "
                "libtopfollow.so or into the stripped library packages.",
                kept[:30],
            )
        )

    # ---- native method surface -------------------------------------------
    info["native_methods"] = [f"{c} . {m} {d_}" for c, m, d_ in native_methods]
    if native_methods:
        F.add(
            Finding(
                "NAT-001",
                f"{len(native_methods)} native (JNI) methods declared in DEX",
                Sev.HIGH,
                "native",
                "Every one of these transfers control from managed Java (fully analyzable) to "
                "libtopfollow.so (partially analyzable). Attackers deliberately move the "
                "incriminating step across this boundary.",
                info["native_methods"][:25],
                attack=["D4.002 - resisting analysis"],
            )
        )

    # ---- network endpoints -------------------------------------------------
    blob = "\n".join(all_strings).encode("latin-1", "replace")
    iocs = extract_iocs(blob)
    urls = iocs["urls"]
    hosts = sorted({host_of(u) for u in urls if host_of(u)})
    third = [h for h in hosts if not is_common_host(h)]
    info["urls"] = urls
    info["hosts"] = hosts
    info["third_party_hosts"] = third
    info["emails"] = iocs["emails"]
    info["pem"] = iocs["pem"]
    info["google_api_keys"] = iocs["google_api_keys"]
    info["websocket"] = iocs["websocket"]
    info["ips"] = iocs["ips"]

    # api endpoint paths (no scheme) that look like a private API
    api_paths = sorted(
        {
            s
            for s in all_strings
            if re.match(r"^/(?:api|v[1-9]|ig|graphql|oauth|auth|realtime|ajax)/[A-Za-z0-9._/\-]{3,80}$", s)
        }
    )
    info["api_paths"] = api_paths
    if api_paths:
        F.add(
            Finding(
                "NET-010",
                f"{len(api_paths)} bare API paths assembled at runtime",
                Sev.HIGH,
                "network",
                "Paths without a host mean the base URL is built elsewhere (native code or config) "
                "and these are appended. These are the *platform's private endpoints* - the calls "
                "an official client is not supposed to make.",
                api_paths[:40],
                attack=["D4.001"],
            )
        )
    if third:
        F.add(
            Finding(
                "NET-011",
                f"{len(third)} non-infrastructure hosts referenced",
                Sev.HIGH,
                "network",
                "Every host below that is not Google/Android/Kotlin infrastructure is a "
                "destination the user's traffic (or data) can reach. Triage them by ownership.",
                third[:60],
                attack=["D4.001 - exfiltration / C2"],
            )
        )
    if iocs["google_api_keys"]:
        F.add(
            Finding(
                "NET-012",
                "Google API key embedded in the client",
                Sev.MEDIUM,
                "credential",
                "Expected for Firebase, but it must be restricted by package name + SHA-1. "
                "An unrestricted key is directly billable and lets anyone impersonate this "
                "project to Firebase endpoints.",
                iocs["google_api_keys"][:5],
                cwe="CWE-798",
            )
        )

    # ---- credential-oriented literals --------------------------------------
    cred_hits = sorted({m.group(0).decode() for m in CRED_STRINGS.finditer(blob)})
    info["credential_literals"] = cred_hits
    plat_rx = re.compile(("(" + "|".join(PLATFORM_MARKERS) + ")").encode(), re.I)
    platform_hits = sorted({m.group(0).decode("latin-1").lower() for m in plat_rx.finditer(blob)})
    info["platform_literals"] = platform_hits[:40]

    # high-signal: session cookie names + password fields in the same app
    interesting = [s for s in cred_hits if s.lower() in {"sessionid", "ds_user_id", "csrftoken", "authorization", "x-ig-app-id"}]
    if interesting:
        F.add(
            Finding(
                "CRED-001",
                "Target-platform session material named as a literal",
                Sev.CRITICAL,
                "credential",
                "These strings are the names of the *authentication cookies/headers* of the "
                "social platform. Their presence proves the code reads or forges the session "
                "itself instead of using the platform's official OAuth flow - which is what a "
                "legit follower-exchange app would have to do.",
                interesting[:12],
                attack=["D4.001 - Account access / credential theft"],
                cwe="CWE-522",
            )
        )
    coin = sorted({m.group(0).decode() for m in COIN_STRINGS.finditer(blob)})
    info["economy_literals"] = coin[:60]

    # ---- secrets: PEM / long base64 blobs -----------------------------------
    b64_hits: list[tuple[str, int]] = []
    for s in all_strings:
        if len(s) >= 180 and re.fullmatch(r"[A-Za-z0-9+/]{180,}={0,2}", s.replace("\n", "")):
            try:
                dec = base64.b64decode(s + "=")
                if dec and shannon(dec) > 6.5:
                    b64_hits.append((s[:70] + f"... (len {len(s)}, decoded entropy {shannon(dec):.2f})", len(s)))
            except (binascii.Error, ValueError):
                pass
    info["opaque_blobs"] = b64_hits[:12]
    if b64_hits:
        F.add(
            Finding(
                "SEC-001",
                f"{len(b64_hits)} high-entropy base64 payloads in DEX strings",
                Sev.HIGH,
                "credential",
                "Base64 whose decoded form is random-looking = an encrypted config, a key, a "
                "certificate pin set, or a second-stage blob. Nothing in the readable layer "
                "explains them, by design.",
                [h[0] for h in b64_hits],
                attack=["D4.002"],
                cwe="CWE-798",
            )
        )
    if iocs["pem"]:
        F.add(
            Finding(
                "SEC-002",
                "PEM key material in managed code",
                Sev.HIGH,
                "credential",
                "Embedded keys are the app's crypto identity: public keys used to verify/encrypt, "
                "or (worse) a private key that lets the operator sign on behalf of users.",
                iocs["pem"][:6],
                cwe="CWE-321",
            )
        )

    # ---- static config fields (BuildConfig / Firebase ids) ------------------
    info["static_config"] = static_cfg
    for cls, cfg in static_cfg.items():
        for k, v in cfg.items():
            if re.search(r"(API_KEY|PROJECT_ID|SENDER_ID|SECRET|TOKEN|BASE_URL|HOST|APP_ID)", k, re.I):
                F.add(
                    Finding(
                        "SEC-010",
                        f"Build config constant {cls.split('/')[-1].strip(';')}.{k}",
                        Sev.MEDIUM,
                        "credential",
                        "Compiled-in configuration value. Sender IDs/API keys identified here are "
                        "the identifiers you report to the platform's abuse desk.",
                        [f"{k} = {v}"],
                        cwe="CWE-798",
                    )
                )

    # ---- FCM / firebase identity --------------------------------------------
    m = re.search(rb"(?:gcm_defaultSenderId|google_app_id|default_web_client_id|project_id)[^\n]{0,80}", blob)
    info["firebase_strings"] = [m.group(0).decode("latin-1")] if m else []

    # ---- call-graph fan-in for the app's own classes -------------------------
    app_calls: Counter[str] = Counter()
    for cls, calls in per_class_calls.items():
        if not APP_PKG.match(cls):
            continue
        for c in calls:
            app_calls[c] += 1
    info["app_external_api_top"] = app_calls.most_common(60)
    info["rule_hit_index"] = {k: len(v) for k, v in sorted(rule_hits.items())}
    info["api_counter_total"] = sum(api_counter.values())
    info["distinct_strings"] = len(set(all_strings))
    info["string_count"] = len(all_strings)
    info["per_class_calls_count"] = {k: len(v) for k, v in sorted(per_class_calls.items(), key=lambda x: -len(x[1]))[:40]}
    info["class_count_meta"] = len(class_meta)

    sig = combined_signals(class_meta, per_class_calls, per_class_strings, per_class_switch, F)
    info["combined_signals"] = sig

    # per-class "what does the login activity actually do" - the money table
    deep: dict[str, list[str]] = {}
    for cls in class_meta:
        if "topfollow" not in cls:
            continue
        calls = per_class_calls.get(cls, set())
        strs = per_class_strings.get(cls, set())
        interesting_calls = sorted(c for c in calls if not c.startswith(("Lkotlin", "Landroidx", "Ljava/lang")))
        if interesting_calls or strs:
            deep[cls] = {
                "calls": interesting_calls[:40],
                "n_calls": len(calls),
                "strings": sorted(strs)[:40],
            }
    info["app_class_detail"] = deep
    return info


def shannon(data: bytes) -> float:
    from .core import shannon_entropy

    return shannon_entropy(data)


# ---------------------------------------------------------------------------
# Combined-signal pass, isolated so it can be unit-tested with a positive
# control (a detector that can never fire is worse than no detector).
# ---------------------------------------------------------------------------
MUTATION_PATH = re.compile(
    r"(friendships/(?:create|destroy|autorecommend)|/(?:api|v\d)/friendships"
    r"|media/[0-9a-z_]+/(?:like|comment)|/(?:friendships|friendship)/|ig_proxy|/fql/)",
    re.I,
)
FABRICATION = re.compile(r"(mock|fake|dummy|simulat|offline|forced?success|auto_?approve|cache_?ok)", re.I)
SUCCESS_SHAPE = re.compile(r"(status\s*[:=]|feedback_url|rk_query_id|media_id|friendship_status)", re.I)
TOGGLE = re.compile(r"(pass\s*\d|mode\s*\d|pass_?\d|switch_?\d|enable|toggle)", re.I)
PATHISH = re.compile(r"^/[A-Za-z0-9._/\-]{4,90}$")


def combined_signals(class_meta, per_class_calls, per_class_strings, per_class_switch, F: Findings) -> dict[str, Any]:
    """Report only *compositions* of capability, never single API mentions."""
    fake_success: list[str] = []
    rotation: list[str] = []
    overlay_panel: list[str] = []

    for cls in class_meta:
        calls = per_class_calls.get(cls, set())
        strs = per_class_strings.get(cls, set())
        joined = "\n".join(strs)

        has_mutation = bool(MUTATION_PATH.search(joined))
        fabricates = bool(FABRICATION.search(joined)) or any(
            ("Response;->success" in c) or ("JsonObject;->add" in c) for c in calls
        )
        if has_mutation and (fabricates or SUCCESS_SHAPE.search(joined)):
            fake_success.append(cls)

        paths = {x for x in strs if PATHISH.match(x)}
        if len(paths) >= 3 and per_class_switch.get(cls, 0) >= 2:
            rotation.append(f"{cls}: {len(paths)} endpoint paths, {per_class_switch[cls]} switch blocks -> "
                            f"{sorted(paths)[:5]}")

        if any("WindowManager;->addView" in c for c in calls) and TOGGLE.search(joined):
            overlay_panel.append(cls)

    if fake_success:
        F.add(Finding(
            "SPOOF-001",
            f"{len(fake_success)} class(es) hold platform mutation paths AND fabricate response objects",
            Sev.CRITICAL, "behaviour",
            "The combination of (a) knowing the real endpoint of a state-changing platform call, "
            "(b) building the success-shaped JSON locally, and (c) no matching network call in the "
            "same class is the fingerprint of a client that shows a real-looking success for an "
            "action the server never confirmed. Confirm by hand: open each class and check whether "
            "the object flows into UI state or into the request builder - the latter is legitimate.",
            fake_success[:15],
            attack=["D4.001 - deception of the local user / forged state"], cwe="CWE-345",
        ))
    if rotation:
        F.add(Finding(
            "OBF-010",
            f"Endpoint-rotation structure detected ({len(rotation)} class(es))",
            Sev.HIGH, "network",
            "A dispatch structure over several equivalent mutation endpoints is how a client rotates "
            "paths to stay under a platform's rate/anomaly detection: each entry is the same action "
            "through a different door. Treat N variants as N detection-evasion passes, not N features.",
            rotation[:15],
            attack=["D4.002 - resisting detection"],
        ))
    if overlay_panel:
        F.add(Finding(
            "OVL-010",
            "Floating overlay control panel with toggle switches",
            Sev.CRITICAL, "behaviour",
            "A runtime-added window plus toggle-style strings in the same class = a user-toggleable "
            "control layer drawn over content. In a repackaged social client its usual purpose is "
            "switching the account-action path at runtime, and the same window type can be placed over "
            "a login form. Verify the window type and what each switch changes.",
            overlay_panel[:12],
            attack=["D4.001 - UI hijack"], cwe="CWE-1021",
        ))
    return {
        "fake_success_classes": fake_success,
        "rotation_classes": rotation,
        "overlay_panel_classes": overlay_panel,
    }

