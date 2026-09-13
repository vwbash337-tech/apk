"""Decode every packed .rodata blob referenced by the network/detection functions.

Three encodings are used in this library and they compose:
  * XOR 0x5A  (func#193's key)            -> ASCII
  * XOR 0x37                                  -> ASCII
  * Base64, applied TWICE (outer layer yields ASCII Base64 again)
The blob at 0x15084 (the signature pin) and the key/nonce blobs at
0x17428/0x17448/0x17458 are all double-Base64, so treat that as the default and
fall back to single Base64 / XOR.
"""
import json, base64, re, string
fm = json.load(open('analysis/funcmap.json'))
d = open('apk_extracted/lib/arm64-v8a/libtopfollow.so', 'rb').read()

B64 = set(string.ascii_letters + string.digits + '+/=')
def cstr(a, maxlen=4096):
    e = d.find(b'\x00', a)
    return d[a:e] if 0 <= e - a < maxlen else b''

def try_b64_layers(s, depth=3):
    out = []
    cur = s
    for _ in range(depth):
        try:
            if not cur or any(c not in B64 for c in cur): break
            if len(cur) % 4: break
            nxt = base64.b64decode(cur, validate=True)
        except Exception:
            break
        out.append(nxt)
        cur = nxt
    return out

def xor(s, k): return bytes(b ^ k for b in s)

def describe(a):
    s = cstr(a)
    if not s: return None
    res = []
    for k in (0x5a, 0x37, 0x20, 0x00):
        t = xor(s, k) if k else s
        layers = try_b64_layers(t)
        for i, L in enumerate(layers):
            if all(32 <= c < 127 for c in L) and len(L) >= 3:
                res.append((f"XOR{k:#02x}->b64x{i+1}", L.decode()))
        if all(32 <= c < 127 for c in t) and len(t) >= 3 and not layers:
            res.append((f"XOR{k:#02x} plain", t.decode()))
    # also: raw bytes may be Base64 of XOR'd data
    for k in (0x5a, 0x37):
        for i, L in enumerate(try_b64_layers(s)):
            t = xor(L, k)
            if all(32 <= c < 127 for c in t) and len(t) >= 3:
                res.append((f"b64x{i+1}->XOR{k:#02x}", t.decode()))
    seen = set(); out = []
    for tag, v in res:
        if v in seen: continue
        seen.add(v); out.append((tag, v))
    return out

TARGETS = ['253', '254', '71', '72', '67', '225', '226', '245', '157', '158', '57',
           '200', '99', '162', '166', '169', '154', '247', '152', '251', '255', '243', '244']
interesting = re.compile(r'(https?://|[a-z0-9-]+\.(com|net|org|io|dev|api|me|co)|instagram|facebook|/api/|/v1/|proc|/system/|su\b|magisk|frida|xposed|gadget|substrate|cwd|maps|status|deleted)', re.I)
for t in TARGETS:
    if t not in fm: continue
    f = fm[t]
    lines = []
    for a in f.get('data_refs', []):
        dec = describe(a)
        if not dec: continue
        for tag, v in dec:
            if interesting.search(v) or len(v) >= 6:
                lines.append(f"    0x{a:06x} [{tag}] {v!r}")
    if lines:
        print(f"\n===== func#{t} @0x{f['start']:x} =====")
        for l in dict.fromkeys(lines): print(l)
