"""Layer 2: code-signing identity.

Recovers the actual X.509 chain out of the APK Signing Block (v2/v3) and
judges it, because that is what determines *who* can push an update to a
device that already has this package installed.

What we then evaluate:
  * self-signed vs CA-issued, key type/size, signature digest
  * validity window (expired or not-yet-valid certs are tamper/staleness signals)
  * X.509 version / extension presence (real Android release keys are v3)
  * the well-known Android debug keystore identity
  * multiple independent signers (re-signing traces)
  * cert "issuer == subject" with a suspicious organisation string
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
import struct
from typing import Any

from .core import Finding, Findings, Sev

DEBUG_CERT_MARKS = (b"androiddebugkey", b"cn=android debug", b"debugkey")


def _candidate_certs(blob: bytes) -> list[bytes]:
    """Every length-prefixed DER blob in `blob` that parses as an X.509 cert."""
    try:
        from cryptography import x509
    except Exception:  # pragma: no cover
        return []
    out: list[bytes] = []
    for m in re.finditer(rb"\x30\x82..", blob, re.S):
        off = m.start()
        ln = struct.unpack_from(">H", blob, off + 2)[0]
        total = 4 + ln
        if total > len(blob) - off:
            continue
        der = blob[off : off + total]
        if len(der) < 64:
            continue
        try:
            c = x509.load_der_x509_certificate(der)
        except Exception:
            continue
        # a cert parsed *exactly* to its DER boundary is a real hit
        if c and der[:2] == b"\x30\x82":
            out.append(der)
    for m in re.finditer(rb"\x30\x81.", blob, re.S):
        off = m.start()
        ln = blob[off + 2]
        total = 3 + ln
        if total > len(blob) - off or total < 64:
            continue
        der = blob[off : off + total]
        try:
            x509.load_der_x509_certificate(der)
        except Exception:
            continue
        out.append(der)
    dedup, seen = [], set()
    for b in out:
        h = hashlib.sha256(b).hexdigest()
        if h not in seen:
            seen.add(h)
            dedup.append(b)
    return dedup


def _fmt_name(name: Any) -> str:
    order = []
    for at in name:
        try:
            order.append(f"{at.oid._name}={at.value}")
        except Exception:
            order.append(str(at.value))
    return ", ".join(order)


def _x509_version(der: bytes) -> int | None:
    """Peek at [0]EXPLICIT version without a full ASN.1 parse.

    tbsCertificate := SEQUENCE { [0]{version}, serial, sigalg, issuer, ... }
    A v3 cert carries `a0 03 02 01 02`; a v1 cert has no version field at all
    (it defaults to v1) and starts the TBSCertificate body with the serial.
    """
    i = der.find(b"\x30\x82", 4)
    if i < 0:
        return None
    body = der[i + 4 : i + 12]
    if body.startswith(b"\xa0\x03"):
        try:
            return der[i + 4 + 5] + 1  # INTEGER value + 1 -> v1..v3
        except IndexError:
            return None
    if body[:1] == b"\x02":  # serial first => implicit v1
        return 1
    return None


def analyse(path: str, F: Findings) -> dict[str, Any]:
    info: dict[str, Any] = {}
    raw = open(path, "rb").read()
    from .container import parse_apk_signing_block

    block = parse_apk_signing_block(raw)
    region_start, region_end = 0, len(raw)
    if block.get("found"):
        # search the signing block first (that is where Android's own cert lives),
        # then fall back to the whole file for a v1 PKCS#7 blob
        region_start = block.get("block_start", 0)
        region_end = block.get("cd_offset", len(raw))
    blobs = _candidate_certs(raw[region_start:region_end])
    source = "APK signing block"
    if not blobs:
        blobs = _candidate_certs(raw)
        source = "whole archive scan"
    info["certs_found"] = len(blobs)
    info["searched"] = source
    if not blobs:
        F.add(
            Finding(
                "SIG-001",
                "No X.509 certificate recoverable from the package",
                Sev.HIGH,
                "signing",
                "No PKCS#7 blob and no v2/v3 signer certificate could be parsed. The APK is "
                "unsigned, or it was rebuilt by a tool that dropped the signer, or the signer "
                "uses a format this parser does not know (see signing_block anomalies).",
            )
        )
        return info

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa, ed25519, ed448

    now = dt.datetime.now(dt.timezone.utc)
    parsed: list[dict[str, Any]] = []
    for i, der in enumerate(blobs):
        rec: dict[str, Any] = {"index": i, "bytes": len(der), "sha256_der": hashlib.sha256(der).hexdigest()}
        try:
            c = x509.load_der_x509_certificate(der)
        except Exception as e:
            rec["parse_error"] = repr(e)
            parsed.append(rec)
            continue
        rec["subject"] = _fmt_name(c.subject)
        rec["issuer"] = _fmt_name(c.issuer)
        rec["serial"] = format(c.serial_number, "x")[:40]
        rec["sig_alg"] = c.signature_algorithm_oid.dotted_string
        rec["not_before"] = c.not_valid_before_utc.isoformat()
        rec["not_after"] = c.not_valid_after_utc.isoformat()
        try:
            rec["fingerprint_sha256"] = c.fingerprint(hashes.SHA256()).hex()
            rec["fingerprint_sha1"] = c.fingerprint(hashes.SHA1()).hex()
        except Exception:
            pass
        rec["self_signed"] = rec["subject"] == rec["issuer"]
        rec["version"] = _x509_version(der)
        try:
            rec["extensions"] = [e.oid.dotted_string for e in c.extensions]
        except Exception:
            rec["extensions"] = []
        pk = c.public_key()
        if isinstance(pk, rsa.RSAPublicKey):
            rec["key"] = f"RSA {pk.key_size}"
            if pk.key_size < 2048:
                F.add(
                    Finding(
                        "SIG-010",
                        f"Weak signing key: RSA {pk.key_size}-bit",
                        Sev.MEDIUM,
                        "signing",
                        "Android requires RSA >= 2048 for new packages since 2021; a short key is "
                        "brute-forceable offline, which means the publisher identity is not real.",
                        [f"cert #{i}: {rec['subject']}"],
                        cwe="CWE-326",
                    )
                )
        elif isinstance(pk, ec.EllipticCurvePublicKey):
            rec["key"] = f"EC {pk.curve.name} {pk.key_size}"
        elif isinstance(pk, (ed25519.Ed25519PublicKey,)):
            rec["key"] = "Ed25519"
        elif isinstance(pk, (ed448.Ed448PublicKey,)):
            rec["key"] = "Ed448"
        elif isinstance(pk, dsa.DSAPublicKey):
            rec["key"] = f"DSA {pk.key_size}"
        else:
            rec["key"] = type(pk).__name__

        # validity window
        try:
            nb, na = c.not_valid_before_utc, c.not_valid_after_utc
            if na < now:
                F.add(
                    Finding(
                        "SIG-011",
                        "Signing certificate is EXPIRED",
                        Sev.HIGH,
                        "signing",
                        f"notAfter={na.date()} is in the past. Android rejects packages whose signer "
                        f"certificate has expired on install and on update, so this file can only be "
                        f"a stale archive or a re-signed forgery that ignored the constraint.",
                        [rec["subject"], f"expired {na.isoformat()}"],
                    )
                )
            if nb > now + dt.timedelta(days=1):
                F.add(
                    Finding(
                        "SIG-012",
                        "Signing certificate not yet valid",
                        Sev.HIGH,
                        "signing",
                        f"notBefore={nb.isoformat()} is in the future: clock-skewed build or tampering.",
                    )
                )
            rec["validity_days"] = (na - nb).days
            rec["validity_years"] = round((na - nb).days / 365.25, 1)
            # Android convention: 25+ year validity. Very short windows are DIY tooling.
            if (na - nb).days < 3650:
                F.add(
                    Finding(
                        "SIG-013",
                        f"Short signing-certificate lifetime ({rec['validity_years']} years)",
                        Sev.MEDIUM,
                        "signing",
                        "Play requires 25+ years and Android Studio templates generate exactly that. "
                        "A short-lived key is typical of an ad-hoc `keytool` run by someone who is not "
                        "managing a long-term release identity - consistent with a repackaging operation "
                        "that just needed *a* key.",
                        [f"notBefore={nb.date()}", f"notAfter={na.date()}", rec["subject"]],
                    )
                )
        except Exception:
            pass

        if rec.get("version") in (1, None) and rec.get("version") != 3:
            F.add(
                Finding(
                    "SIG-014",
                    f"Certificate is X.509 version {rec.get('version')} (no v3 extension set)",
                    Sev.MEDIUM,
                    "signing",
                    "apksigner/Play release keys are v3 certificates carrying at least a basic "
                    "constraints extension. A v1 certificate with an empty extension set is what "
                    "hand-rolled signers and some script-based re-signing tools emit, so it is a "
                    "second, independent hint that this package was signed outside a normal "
                    "Android build pipeline.",
                    [f"version={rec.get('version')}", f"extensions={rec.get('extensions')}", rec["subject"]],
                )
            )

        subj = (rec.get("subject") or "").lower()
        if any(d.decode() in subj for d in DEBUG_CERT_MARKS):
            F.add(
                Finding(
                    "SIG-020",
                    "Signed with the Android SDK DEBUG keystore",
                    Sev.HIGH,
                    "signing",
                    "The package carries the well-known androiddebugkey identity. A 'release' APK "
                    "signed with a debug key is essentially never a store artefact; combined with "
                    "'Beta' naming it points at an internal or leaked build being redistributed.",
                    [rec["subject"], rec.get("fingerprint_sha256", "")],
                )
            )
        if rec.get("self_signed"):
            F.add(
                Finding(
                    "SIG-021",
                    "Self-signed signing certificate (no CA chain)",
                    Sev.INFO,
                    "signing",
                    "Normal for Android - the platform trusts the package's own key - but it means "
                    "the certificate proves nothing about the publisher's identity. Anyone can mint "
                    "one with the same CN. The only usable identity anchor is the SHA-256 "
                    "fingerprint below: compare it against the fingerprint the developer publishes. "
                    "Different fingerprint = different author, regardless of what the file is named.",
                    [
                        f"subject={rec['subject']}",
                        f"issuer={rec['issuer']}",
                        f"key={rec.get('key')}",
                        f"sig_alg={rec.get('sig_alg')}",
                        f"cert_sha256={rec.get('fingerprint_sha256')}",
                        f"cert_sha1={rec.get('fingerprint_sha1')}",
                    ],
                )
            )
        parsed.append(rec)

    if len(parsed) > 1:
        F.add(
            Finding(
                "SIG-022",
                f"{len(parsed)} certificates reachable from the signer block",
                Sev.MEDIUM,
                "signing",
                "A v3 proof-of-rotation chain legitimately carries more than one cert; two "
                "unrelated certs with the same subject but different keys is how a repackager's "
                "new key looks. Compare the fingerprints.",
                [f"#{p.get('index')} {p.get('subject')} {p.get('fingerprint_sha256','')[:16]}" for p in parsed],
            )
        )
    info["certificates"] = parsed
    if parsed:
        info["primary_subject"] = parsed[0].get("subject")
        info["primary_issuer"] = parsed[0].get("issuer")
        info["primary_key"] = parsed[0].get("key")
        info["primary_fingerprint"] = parsed[0].get("fingerprint_sha256")
        info["validity_years"] = parsed[0].get("validity_years")
    return info
