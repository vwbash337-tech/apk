"""Shared primitives for the APK static-audit engine.

Design goals:
  * zero mandatory third-party deps for the container/signing/native layers,
  * androguard is used opportunistically for AXML + DEX and everything
    degrades gracefully when it is unavailable,
  * every finding carries machine-usable evidence so the report, the JSON
    dump and the SARIF export all come from one source of truth.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import struct
import zlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Iterable, Iterator


# --------------------------------------------------------------------------
# Severity model
# --------------------------------------------------------------------------
class Sev(IntEnum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

    @property
    def label(self) -> str:
        return self.name.title()

    @property
    def emoji(self) -> str:
        return {
            Sev.CRITICAL: "\U0001f534",
            Sev.HIGH: "\U0001f7e0",
            Sev.MEDIUM: "\U0001f7e1",
            Sev.LOW: "\U0001f535",
            Sev.INFO: "\u26aa",
        }[self]


# Rough weights used for the aggregate risk score.
SEV_WEIGHT = {
    Sev.CRITICAL: 10.0,
    Sev.HIGH: 5.0,
    Sev.MEDIUM: 2.0,
    Sev.LOW: 0.75,
    Sev.INFO: 0.0,
}


@dataclass
class Finding:
    """One atomic, evidence-backed observation about the sample."""

    rule_id: str
    title: str
    severity: Sev
    category: str
    detail: str = ""
    evidence: list[str] = field(default_factory=list)
    # MITRE ATT&CK for Mobile (D4.x tactics / techniques) where applicable.
    attack: list[str] = field(default_factory=list)
    # Where to look next, for a human reversing this by hand.
    refs: list[str] = field(default_factory=list)
    cwe: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.name,
            "category": self.category,
            "detail": self.detail,
            "evidence": self.evidence[:40],
            "attack": self.attack,
            "refs": self.refs,
            "cwe": self.cwe,
        }


class Findings:
    """Collector with de-duplication and scoring."""

    def __init__(self) -> None:
        self.items: list[Finding] = []
        self._seen: set[tuple[str, str]] = set()

    def add(self, f: Finding) -> None:
        key = (f.rule_id, f.title)
        if key in self._seen:
            # merge evidence instead of duplicating the row
            for prev in reversed(self.items):
                if (prev.rule_id, prev.title) == key:
                    prev.evidence.extend(f.evidence)
                    prev.detail = prev.detail or f.detail
                    break
            return
        self._seen.add(key)
        self.items.append(f)

    def __len__(self) -> int:
        return len(self.items)

    def by_severity(self, sev: Sev) -> list[Finding]:
        return [f for f in self.items if f.severity is sev]

    def score(self) -> tuple[float, str]:
        """Weighted 0-100 risk score plus a coarse verdict band."""
        raw = sum(SEV_WEIGHT[f.severity] for f in self.items)
        # Saturating curve: many low-severity rows must not read as "critical".
        score = 100.0 * (1.0 - math.exp(-raw / 34.0))
        band = (
            "CRITICAL"
            if score >= 75
            else "HIGH"
            if score >= 50
            else "ELEVATED"
            if score >= 30
            else "MODERATE"
            if score >= 15
            else "LOW"
        )
        return round(score, 1), band


# --------------------------------------------------------------------------
# IOC / secret extraction
# --------------------------------------------------------------------------
RE_URL = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%\-]{6,300}")
RE_WS = re.compile(rb"(?:wss?)://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%\-]{6,300}")
RE_IP = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_EMAIL = re.compile(rb"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
RE_DOMAIN = re.compile(
    rb"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    rb"(?:com|net|org|io|app|dev|co|ai|xyz|ru|cn|in|ir|vn|id|br|tr|ua|me|tk|ml|ga|cf|gq|top|vip|club|site|online|live|shop|info|biz|cloud|tech|social|network|api|gg|to|ly|im|fm|sh|so|is|cc|tv|eu|de|fr|nl|pl|ro|bg|cz|hu|gr|it|es|pt|jp|kr|tw|hk|sg|my|th|ph|nz|au|za|ng|ke|eg|sa|ae|qa|kw|om|jo|lb|iq|pk|bd|np|lk|kz|by|md|rs|hr|si|sk|lt|lv|ee|fi|se|no|dk|be|at|ch|ie)\b"
)
RE_B64 = re.compile(rb"\b(?:[A-Za-z0-9+/]{4}){12,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
RE_HEXKEY = re.compile(rb"\b[0-9a-fA-F]{32,128}\b")
RE_PEM = re.compile(rb"-----BEGIN [A-Z ]*-----.{0,4000}?-----END [A-Z ]*-----", re.S)
RE_GOOGLE_KEY = re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b")
RE_FCM_SENDER = re.compile(rb"\b\d{9,12}\b")
RE_AWS = re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
RE_STRIPE = re.compile(rb"\b[spr]k_(?:live|test)_[0-9A-Za-z]{16,}\b")
RE_FB_APP = re.compile(rb"\b[0-9]{9,12}\b")
RE_JWT = re.compile(rb"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b")
RE_TG_BOT = re.compile(rb"\b\d{8,10}:AA[A-Za-z0-9_\-]{30,}\b")
RE_PKCS = re.compile(rb"\.p12|\.pfx|\.keystore|\.jks|\.bks", re.I)
RE_PHONE_ID = re.compile(rb"\+?\d{1,3}[ .\-]?\(?\d{2,4}\)?[ .\-]?\d{3,4}[ .\-]?\d{4}")

# Hosts that are *expected* in a mainstream app; anything else is notable.
ALLOWED_HINTS = (
    b"googleapis.com",
    b"google.com",
    b"gstatic.com",
    b"firebase",
    b"firebaseio.com",
    b"firebase-settings",
    b"crashlytics",
    b"android.com",
    b"schema.org",
    b"w3.org",
    b"apache.org",
    b"unicode.org",
    b"openoffice",
    b"sun.com",
    b"oracle.com",
    b"okhttp",
    b"squareup",
    b"kotlinlang",
    b"github.com",
    b"githubusercontent",
)


def shannon_entropy(data: bytes) -> float:
    """Bits per byte, 0..8. Used to spot encrypted/packed blobs."""
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def printable(data: bytes) -> bool:
    return all(0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D) for b in data)


def dedupe(seq: Iterable[str]) -> list[str]:
    out, seen = [], set()
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def iter_strings(blob: bytes, min_len: int = 5) -> Iterator[bytes]:
    """ASCII + UTF-16LE runs, the way `strings` does, minus the noise."""
    i, n = 0, len(blob)
    while i < n:
        b = blob[i]
        if 0x20 <= b < 0x7F:
            j = i
            while j < n and (0x20 <= blob[j] < 0x7F or blob[j] in (0x09,)):
                j += 1
            if j - i >= min_len:
                yield blob[i:j]
            i = j
        elif b not in (0x00,) and i + 1 < n and 0x20 <= blob[i + 1] == blob[i + 1] and 0x20 <= blob[i + 1] < 0x7F and blob[i] == 0:
            # UTF-16LE ascii: high byte zero, low byte printable
            j = i
            while j + 1 < n and blob[j] == 0 and 0x20 <= blob[j + 1] < 0x7F:
                j += 2
            if (j - i) // 2 >= min_len:
                yield blob[i:j:2]
            i = j
        else:
            i += 1


def extract_iocs(blob: bytes) -> dict[str, list[str]]:
    """Pull every network / credential-ish artefact out of a byte blob."""
    def uniq(rx: re.Pattern[bytes], cap: int = 400) -> list[str]:
        seen: list[str] = []
        got: set[str] = set()
        for m in rx.finditer(blob):
            s = m.group(0).decode("latin-1").rstrip(".,;:\"')")
            if s not in got:
                got.add(s)
                seen.append(s)
            if len(seen) >= cap:
                break
        return seen

    return {
        "urls": uniq(RE_URL),
        "websocket": uniq(RE_WS),
        "ips": uniq(RE_IP, 60),
        "emails": uniq(RE_EMAIL, 80),
        "domains": uniq(RE_DOMAIN, 300),
        "pem": [p[:220].replace("\n", "\\n") for p in uniq(RE_PEM, 12)],
        "google_api_keys": uniq(RE_GOOGLE_KEY, 20),
        "aws_keys": uniq(RE_AWS, 20),
        "stripe_keys": uniq(RE_STRIPE, 20),
        "jwt": uniq(RE_JWT, 10),
        "telegram_bots": uniq(RE_TG_BOT, 10),
        "hexblobs": uniq(RE_HEXKEY, 40),
        "keystore_refs": uniq(RE_PKCS, 20),
    }


def split_url(url: str) -> tuple[str, str]:
    """(host, path) for a captured URL."""
    m = re.match(r"^(?:https?|wss?)://([^/]+)(/.*)?$", url)
    if not m:
        return url, ""
    return m.group(1).lower(), m.group(2) or ""


def host_of(url: str) -> str:
    return split_url(url)[0]


def is_common_host(host: str) -> bool:
    h = host.lower().encode()
    return any(a in h for a in ALLOWED_HINTS)


# --------------------------------------------------------------------------
# Small helpers used by several layers
# --------------------------------------------------------------------------
def u8(b: bytes, o: int) -> int:
    return b[o]


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def u64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


def s32(b: bytes, o: int) -> int:
    return struct.unpack_from("<i", b, o)[0]


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"


def dump_json(path: str, obj: Any) -> None:
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=1, sort_keys=False, default=str)


def crc32_of(blob: bytes) -> int:
    return zlib.crc32(blob) & 0xFFFFFFFF


def file_hashes(path: str) -> dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "size": str(os_stat(path)),
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def os_stat(path: str) -> int:
    import os

    return os.path.getsize(path)
