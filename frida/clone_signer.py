#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
clone_signer.py — banaiye ek *byte-identical* signing certificate clone
=========================================================================

TopFollow ka native library APK ke signing certificate ka SHA-256 pin karta hai
(`func#226 @ 0x159c10` aur `func#73 @ 0x103ad8`, dono Java se
`PackageManager.getPackageInfo(pkg, GET_SIGNATURES)` upcall karke
`Signature.toByteArray()` par `MessageDigest("SHA-256")` chalate hain):

    pinned = d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e

Yeh digest **original signer certificate ke DER bytes** ka SHA-256 hai.
Hum verify kar chuke hain:

    SHA-256(original_signer_cert.der) == pinned      (exact match)

Private key humare paas nahi hai, isliye hum certificate ko **rebuild** karte
hain: same version / serial / signature-algorithm / issuer+subject DN /
notBefore / notAfter / extensions, sirf public key naya. Isse `apksigner`
se sign kiya hua repackaged APK **v1 (JAR) signature scheme** mein exactly
wahi certificate present karega.

IMPORTANT — honest limitation
-----------------------------
Android 7+ `PackageManager` ko signature **APK Signing Block (v2/v3)** se deta
hai, `META-INF/*.RSA` se nahi. Humare paas original private key nahi hai, isliye
v2/v3 block mein clone cert nahi ja sakta — wahan humara naya self-signed cert
hi rahega. Matlab:

  * Native check ko pass karane ke liye agent ka Java-side
    `getPackageInfo` forgery hook **zaroori** hai (topfollow_agent.js §7.4).
    Woh hook `PackageInfo.signatures[0]` mein ORIGINAL cert ke DER bytes daal
    deta hai, to native SHA-256 pinned value se match ho jata hai.
  * Yeh script sirf itna karta hai ki v1 scheme bhi present rahe aur agar
    koi code path `META-INF` se cert padhe to use original cert mile.

Output (frida/keys/ ke andar):
    topfollow_clone.p12     PKCS#12 keystore  (alias "topfollow", pass "topfollow")
    topfollow_clone.jks     same, JKS (agar BKS/PKCS12 mein dikkat aaye)
    clone_key.pem           private key (PKCS#8, unencrypted)
    clone_cert.der          original cert ke DER bytes (agent isi ko forge karta hai)
    clone_cert.pem          PEM form

Usage:
    python3 frida/clone_signer.py                     # default output frida/keys/
    python3 frida/clone_signer.py --apk TopFollow_v845-Beta.apk --outdir /tmp/k
    python3 frida/clone_signer.py --keysize 2048 --days-to-expire 9131
"""
import argparse
import base64
import datetime as dt
import hashlib
import os
import sys

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID
except ImportError:
    sys.exit("cryptography package chahiye:  pip install cryptography")

# ---------------------------------------------------------------------------
# The ORIGINAL signer certificate, verbatim, extracted from the APK Signing
# Block of TopFollow_v845-Beta.apk.  864 bytes DER.  Its SHA-256 IS the value
# pinned in libtopfollow.so at 0x15084, so this blob is not a guess.
# ---------------------------------------------------------------------------
ORIGINAL_CERT_B64 = (
    "MIIDXDCCAkQCAQEwDQYJKoZIhvcNAQELBQAwdDEWMBQGA1UEAwwNTWFyeWFtIEFo"
    "bWFkaTEaMBgGA1UECwwRQW5kcm9pZCBEZXZlbG9wZXIxETAPBgNVBAoMCE5pdmFS"
    "b2lkMQ8wDQYDVQQHDAZTaGlyYXoxDTALBgNVBAgMBEZhcnMxCzAJBgNVBAYTAklS"
    "MB4XDTIzMTIxNTE3NDQzM1oXDTQ4MTIwODE3NDQzM1owdDEWMBQGA1UEAwwNTWFy"
    "eWFtIEFobWFkaTEaMBgGA1UECwwRQW5kcm9pZCBEZXZlbG9wZXIxETAPBgNVBAoM"
    "CE5pdmFSb2lkMQ8wDQYDVQQHDAZTaGlyYXoxDTALBgNVBAgMBEZhcnMxCzAJBgNV"
    "BAYTAklSMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi/269b1INF5S"
    "kw5rIyOK5pxMo4MikftNxHGz6MV3/StA/296zXWMND35vdcIR0i3HZ+dr2FIagZB"
    "Oyo5rgF1pnlAwocuzLutEUdS9gEWyp/SfLGWp1LKx5zRclHAgE47BlOCApJ+7BX8"
    "/s7k0hda5aYmhPYFUBniZ8cmnHH9l+H2F6XJZuyhzRSWgZlLoIm3Y36rjKlXllnD"
    "5tOTKF0ugHx1jV6UagJ5bzjy4e4eOMmxPslcp2fDt3w6V7daECrRmBWGh1PikQgb"
    "V2W8qi9mtx8NUZoSxNVcCLA9kyoR6TduACOtB379GdTgu8irEwge/v1ChEWKafw/"
    "aA/w2cQh3QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAH666jLbCTDshkgo2G6QTk"
    "UtArzfHmI2HiozoljfXW3FHgxv6abfH39v03c5lfPLyQT3DcTI413ZddNNtLsJRC"
    "4D40gX/hqqe6PRt/xi0xPsPZZ2InwptNEYv94iLhLl80PFsNu4ORD+4VmysijRcG"
    "OZFb5hHud7advS4n1NzltowmyZC2Skl4PrznEjhqDZ+3Rz+nS68vRflPvsw91KXI"
    "ktk0npzK0whtHZNAg8XJkdsGuPtrCv8o6jgqJtotCTuK1H3TNEUrzAmf24Uzt6hI"
    "T5PKjYDRll7kdQlqH7H+/bKgdE0nWIYiy807rmjXMpgJQRXWQAythbTkWPtWLAeT"
)

PINNED_SHA256 = "d845591e086033a9035fd6b66c3c3d73aa33af90794d6b986e64779eea6bec5e"


def log(msg):
    print(msg, flush=True)


def original_cert_der():
    return base64.b64decode(ORIGINAL_CERT_B64)


def verify_against_apk(apk_path):
    """Cross-check the embedded blob against the real APK (if available)."""
    if not apk_path or not os.path.exists(apk_path):
        log("  [skip] APK nahi mila (%s) — embedded blob use ho raha hai" % apk_path)
        return None
    try:
        from androguard.core.apk import APK
    except ImportError:
        log("  [skip] androguard nahi hai, APK cross-check skip")
        return None
    try:
        a = APK(apk_path)
        certs = a.get_certificates()
        if not certs:
            log("  [warn] APK se koi certificate nahi mila")
            return None
        der = certs[0].dump()
        same = der == original_cert_der()
        log("  [%s] APK cert DER == embedded blob  (%d bytes)" % ("OK" if same else "MISMATCH", len(der)))
        if not same:
            log("        APK sha256 = %s" % hashlib.sha256(der).hexdigest())
            log("        blob sha256= %s" % hashlib.sha256(original_cert_der()).hexdigest())
        return der
    except Exception as e:
        log("  [warn] APK cross-check fail: %s" % e)
        return None


def verify_against_so(so_path):
    """Read the pin blob straight out of libtopfollow.so and decode it.

    @0x15084 the library stores, IN PLAINTEXT (no XOR-0x5A), a 120-char string
    that is Base64(Base64(hexdigest)).  Two rounds of Base64 give the 64-char
    SHA-256 that func#226 / func#73 compare `MessageDigest("SHA-256")
    .digest(Signature.toByteArray())` against.  Verified exact:

        b64d(b64d(blob @0x15084)) == d845591e...eea6bec5e == SHA-256(orig cert)
    """
    if not so_path or not os.path.exists(so_path):
        log("  [skip] libtopfollow.so nahi mila (%s)" % so_path)
        return None
    try:
        with open(so_path, "rb") as f:
            f.seek(0x15084)
            raw = f.read(256)
        end = raw.find(b"\x00")
        blob = raw[:end if end > 0 else len(raw)].decode("ascii", "strict").strip()
        l1 = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("ascii")
        l2 = base64.b64decode(l1 + "=" * (-len(l1) % 4)).decode("ascii")
        ok = (l2 == PINNED_SHA256)
        log("  [%s] .so @0x15084 : %d-char plaintext blob" % ("OK" if ok else "MISMATCH", len(blob)))
        log("        %s" % blob[:72] + ("..." if len(blob) > 72 else ""))
        log("        b64decode x1 -> %d chars" % len(l1))
        log("        b64decode x2 -> %s" % l2)
        if not ok:
            log("        expected     -> %s" % PINNED_SHA256)
        return l2
    except Exception as e:
        log("  [warn] .so pin blob read fail: %s" % e)
        return None


def build_clone(keysize=2048, e=65537):
    """Rebuild the certificate with a fresh key, keeping every other field —
       including the exact UTC validity timestamps — byte-identical."""
    der = original_cert_der()
    orig = x509.load_der_x509_certificate(der)

    key = rsa.generate_private_key(public_exponent=e, key_size=keysize)

    nb = orig.not_valid_before_utc.replace(tzinfo=None)
    na = orig.not_valid_after_utc.replace(tzinfo=None)

    b = (x509.CertificateBuilder()
         .subject_name(orig.subject)
         .issuer_name(orig.issuer)              # self-signed: issuer == subject
         .public_key(key.public_key())
         .serial_number(orig.serial_number)
         .not_valid_before(nb)
         .not_valid_after(na))
    for ext in orig.extensions:
        b = b.add_extension(ext.value, critical=ext.critical)

    cert = b.sign(private_key=key, algorithm=hashes.SHA256())

    # ---- structural verification: the TBS part must be byte-identical ----
    new_der = cert.public_bytes(serialization.Encoding.DER)
    tbs_len_new = _der_seq_len(new_der)
    tbs_len_old = _der_seq_len(der)
    tbs_ok = new_der[4:4 + tbs_len_new] == der[4:4 + tbs_len_old]
    return key, cert, new_der, tbs_ok, orig


def _der_seq_len(buf):
    """length of the first DER SEQUENCE (header included) at buf[0:]"""
    assert buf[0] == 0x30
    l = buf[1]
    if l & 0x80:
        n = l & 0x7F
        return 2 + n + int.from_bytes(buf[2:2 + n], "big")
    return 2 + l


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    ap.add_argument("--outdir", default=os.path.join(here, "keys"))
    ap.add_argument("--apk", default=os.path.join(root, "TopFollow_v845-Beta.apk"))
    ap.add_argument("--so", default=os.path.join(root, "work", "apk_extracted", "lib",
                                                 "arm64-v8a", "libtopfollow.so"))
    ap.add_argument("--keysize", type=int, default=2048)
    ap.add_argument("--password", default="topfollow")
    ap.add_argument("--alias", default="topfollow")
    a = ap.parse_args()

    log("=" * 78)
    log("clone_signer.py — original TopFollow signer certificate ka clone")
    log("=" * 78)

    der = original_cert_der()
    sha = hashlib.sha256(der).hexdigest()
    log("\n[1] ORIGINAL CERTIFICATE (APK Signing Block se nikala hua)")
    log("    DER size          : %d bytes" % len(der))
    log("    SHA-256(DER)      : %s" % sha)
    log("    pinned @0x15084   : %s" % PINNED_SHA256)
    if sha != PINNED_SHA256:
        sys.exit("    FATAL: digest pinned value se match nahi karta — aage mat badho")
    log("    --> MATCH. Yehi woh certificate hai jiska digest libtopfollow.so pin karta hai.")

    log("\n[2] CROSS-CHECKS")
    verify_against_apk(a.apk)
    verify_against_so(a.so)

    log("\n[3] CLONE BANANA (naya RSA-%d key, baaki sab fields identical)" % a.keysize)
    key, cert, new_der, tbs_ok, orig = build_clone(keysize=a.keysize)
    log("    subject           : %s" % cert.subject.rfc4514_string())
    log("    serial            : %d" % cert.serial_number)
    log("    notBefore (UTC)   : %s" % cert.not_valid_before_utc.isoformat())
    log("    notAfter  (UTC)   : %s" % cert.not_valid_after_utc.isoformat())
    log("    signature algo    : %s" % cert.signature_algorithm_oid.dotted_string)
    log("    clone DER size    : %d bytes (original %d)" % (len(new_der), len(der)))
    log("    TBS bytes identical: %s" % ("YES" if tbs_ok else "NO (size differ karta hai, "
                                                            "kyunki public key naya hai)"))
    log("    clone SHA-256(DER): %s   <-- original se DIFFERENT (expected)"
        % hashlib.sha256(new_der).hexdigest())

    os.makedirs(a.outdir, exist_ok=True)
    p12 = pkcs12.serialize_key_and_certificates(
        name=a.alias.encode(),
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(a.password.encode()))
    p12_path = os.path.join(a.outdir, "topfollow_clone.p12")
    with open(p12_path, "wb") as f:
        f.write(p12)

    key_path = os.path.join(a.outdir, "clone_key.pem")
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    cert_path = os.path.join(a.outdir, "clone_cert.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    der_path = os.path.join(a.outdir, "original_cert.der")
    with open(der_path, "wb") as f:
        f.write(der)
    b64_path = os.path.join(a.outdir, "original_cert.b64")
    with open(b64_path, "w") as f:
        f.write(base64.b64encode(der).decode() + "\n")

    log("\n[4] FILES")
    for p in (p12_path, key_path, cert_path, der_path, b64_path):
        log("    %-56s %6d B" % (p, os.path.getsize(p)))

    log("""
[5] AB AAPKO APNE PC PAR YEH KARNA HAI
--------------------------------------
(a) BKS keystore banaiye (Android ka default keystore type):

    keytool -importkeystore \\
      -srckeystore  frida/keys/topfollow_clone.p12 -srcstoretype PKCS12 \\
      -srcstorepass topfollow -srcalias topfollow \\
      -destkeystore frida/keys/topfollow_clone.bks -deststoretype BKS \\
      -deststorepass topfollow -destalias topfollow \\
      -providerclass org.bouncycastle.jce.provider.BouncyCastleProvider \\
      -providerpath bcprov-jdk18on-1.78.1.jar

    (BouncyCastle jar: https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/)

    Agar BKS banane mein jhanjat ho to seedha PKCS12 use kar lijiye — apksigner
    `--ks-key-alias topfollow --ks-pass pass:topfollow` ke saath PKCS#12 ko
    bhi padh leta hai (`--ks frida/keys/topfollow_clone.p12`).

(b) Sign karte waqt v1 scheme ZAROOR enable kijiye, warna clone cert ka koi
    fayda nahi (Android 7+ default mein v2/v3 use karta hai aur v1 chhod deta
    hai, aur original APK mein v1 signature hai hi nahi):

    apksigner sign --ks frida/keys/topfollow_clone.p12 --ks-pass pass:topfollow \\
      --ks-key-alias topfollow \\
      --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \\
      --out TopFollow_v845-gadget.apk  TopFollow_v845-gadget-aligned.apk

(c) Native check tab bhi fail hoga kyunki PackageManager v2/v3 block se cert
    deta hai. Isliye topfollow_agent.js ka `spoofSignature` hook ON rakhiye
    (default ON) — woh getPackageInfo() ke jawab mein ORIGINAL cert ke DER
    bytes daal deta hai, aur SHA-256 pinned value se match kar jata hai.

    Verify karne ke liye agent mein:   rpc.exports.signature()
""")


if __name__ == "__main__":
    main()
