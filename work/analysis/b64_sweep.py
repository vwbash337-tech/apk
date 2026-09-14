"""Sweep every C string in .rodata for Base64 (1..3 layers) and for XOR+Base64.

Prints anything that decodes to printable ASCII containing a URL, a hostname, a
path, or a known detection token.  This is how the API endpoints hidden behind the
double-Base64 layer are enumerated without guessing.
"""
import re, base64, string, sys
d = open('apk_extracted/lib/arm64-v8a/libtopfollow.so', 'rb').read()
RO = (0x14000, 0x1c000)      # generous .rodata window for this build
B64 = set((string.ascii_letters + string.digits + '+/=').encode())
PRINT = set(range(32, 127))
pat = re.compile(rb'[A-Za-z0-9+/]{8,}={0,2}')
want = re.compile(r'(https?://|[a-z0-9-]+\.(com|net|org|io|dev|api|me|co|ir|info|xyz|site|online|shop|store)([:/]|$)|/api/|/v1/|/v2/|instagram|facebook|whatsapp|telegram|proc/|/system/|magisk|frida|xposed|gadget|substrate|supolicy|daemonsu|busybox|/sbin/|order|token|licence|license|activate|verify)', re.I)

def dec_layers(s, depth=3):
    out = []; cur = s
    for _ in range(depth):
        if not cur or len(cur) % 4 or any(c not in B64 for c in cur): break
        try: nxt = base64.b64decode(cur, validate=True)
        except Exception: break
        out.append(nxt); cur = nxt
    return out

hits = {}
for m in pat.finditer(d, RO[0], RO[1]):
    s = m.group(0)
    for i, L in enumerate(dec_layers(s)):
        if all(c in PRINT for c in L) and len(L) >= 4:
            t = L.decode()
            if want.search(t):
                hits.setdefault(t, set()).add((hex(m.start()), i + 1))
    for k in (0x5a, 0x37):
        x = bytes(b ^ k for b in s)
        for i, L in enumerate(dec_layers(x)):
            if all(c in PRINT for c in L) and len(L) >= 4:
                t = L.decode()
                if want.search(t):
                    hits.setdefault(t, set()).add((hex(m.start()), f'XOR{k:#x}+b64x{i+1}'))
for t in sorted(hits):
    print(f"  {t!r}\n      from {sorted(hits[t])}")
print(f"\ntotal distinct decoded strings of interest: {len(hits)}")
