import re,base64,json,collections
raw=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
fm=json.load(open('analysis/funcmap.json'))
inv=collections.defaultdict(set)
for t,v in fm.items():
    for a in v['data_refs']: inv[a].add(int(t))
def owners(va):
    s=set()
    for d in range(-8,9): s|=inv.get(va+d,set())
    return sorted(s)
print("=== all 16-char Base64 strings (=> 12 bytes = AES-GCM 96-bit key/nonce) ===")
for m in re.finditer(rb'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16}(?![A-Za-z0-9+/=])',raw[0x10000:0x18000]):
    va=0x10000+m.start();s=m.group(0)
    try: dd=base64.b64decode(s,validate=True)
    except Exception: continue
    if len(dd)!=12: continue
    txt=dd.decode('latin1')
    pr=''.join(chr(c) if 32<=c<127 else '.' for c in dd)
    print(f"  0x{va:06x} {s.decode():18s} -> {dd.hex()} |{pr}| refs={owners(va)}")
print()
print("=== all 24/32/44-char Base64 (=> 18/24/33 bytes) & 32-char (=>24B AES-192) ===")
for L in (24,32,44,48,64):
    for m in re.finditer(rb'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{%d}={0,2}(?![A-Za-z0-9+/=])'%L,raw[0x10000:0x18000]):
        va=0x10000+m.start();s=m.group(0)
        if len(s)%4: continue
        try: dd=base64.b64decode(s,validate=True)
        except Exception: continue
        if len(dd) not in (16,24,32,36,48): continue
        pr=''.join(chr(c) if 32<=c<127 else '.' for c in dd)
        print(f"  len{L} 0x{va:06x} {s.decode()[:48]:50s} -> {len(dd):2d}B |{pr[:46]}| refs={owners(va)}")
print()
print("=== multi-layer: decode nested Base64 found above ===")
for s in (b'V1ZWb1UwMUhUa2xVVkZwTlpWUm5PUT09',b'WXpKV2JHSnBPRDA9',b'U0dKR01FNW9OV3h3',b'5VEJK9Uk4d0elpVT'):
    cur=s;chain=[s.decode()]
    for _ in range(5):
        try: nxt=base64.b64decode(cur,validate=True)
        except Exception: break
        if not re.fullmatch(rb'[A-Za-z0-9+/]+={0,2}',nxt): 
            chain.append(nxt.hex());break
        chain.append(nxt.decode());cur=nxt
    print(f"  {' -> '.join(chain)}")
print()
print("=== literal ASCII 16/24/32-byte key candidates in .rodata ===")
for m in re.finditer(rb'(?<![A-Za-z0-9])([0-9a-f]{16}|[0-9a-f]{32}|[0-9a-f]{64})(?![0-9a-f])',raw[0x10000:0x18000]):
    va=0x10000+m.start();print(f"  0x{va:06x} {m.group(0).decode()!r} refs={owners(va)}")
