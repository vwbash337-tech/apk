"""Enumerate EVERY Base64-hidden C string in .rodata (all layer counts) and map
each one to the function(s) that reference its address."""
import re, base64, string, json, bisect
d = open('apk_extracted/lib/arm64-v8a/libtopfollow.so', 'rb').read()
fm = json.load(open('analysis/funcmap.json'))
starts = sorted((int(v['start']), int(i), int(v['size'])) for i, v in fm.items())
sa = [s for s, _, _ in starts]
def owner(a):
    i = bisect.bisect_right(sa, a) - 1
    if i >= 0 and a < starts[i][0] + starts[i][2]: return f"func#{starts[i][1]}"
    return '-'
# data-ref index: address -> referencing funcs
refmap = {}
for i, f in fm.items():
    for a in f.get('data_refs', []): refmap.setdefault(a, []).append(int(i))

B64 = set((string.ascii_letters + string.digits + '+/=').encode())
PRINT = set(range(32, 127))
pat = re.compile(rb'[A-Za-z0-9+/]{6,}={0,2}')
rows = []
seen = set()
for m in pat.finditer(d, 0x13000, 0x1c000):
    s = m.group(0); cur = s
    for depth in range(1, 4):
        if len(cur) % 4 or any(c not in B64 for c in cur): break
        try: nxt = base64.b64decode(cur, validate=True)
        except Exception: break
        if all(c in PRINT for c in nxt) and len(nxt) >= 3:
            t = nxt.decode()
            key = (hex(m.start()), depth)
            if key not in seen:
                seen.add(key)
                refs = sorted(refmap.get(m.start(), []))
                rows.append((m.start(), depth, t, refs))
        cur = nxt
rows.sort()
for off, depth, t, refs in rows:
    r = ','.join(f'#{x}' for x in refs) if refs else '(no direct data-ref)'
    print(f"  0x{off:05x} b64x{depth}  {t!r:<62} refs={r}")
print(f"\n{len(rows)} decoded strings")
