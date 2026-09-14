import re,base64,json,collections
raw=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
fm=json.load(open('analysis/funcmap.json'))
inv=collections.defaultdict(set)
for t,v in fm.items():
    for a in v['data_refs']: inv[a].add(int(t))
def owners(va):
    s=set()
    for d in range(-10,11): s|=inv.get(va+d,set())
    return sorted(s)
B=re.compile(rb'(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])')
out=[]
for m in B.finditer(raw[0x10000:0x18000]):
    va=0x10000+m.start();s=m.group(1)
    if len(s)%4: continue
    chain=[];cur=s
    for _ in range(6):
        try: dd=base64.b64decode(cur,validate=True)
        except Exception: break
        if dd==b'' : break
        chain.append(dd)
        if not B.fullmatch(dd): break
        cur=dd
    if len(chain)>=2:
        final=chain[-1]
        pr=''.join(chr(c) if 32<=c<127 else '.' for c in final)
        out.append((va,len(chain),s.decode(),pr,owners(va)))
out.sort(key=lambda x:-x[1])
print(f"=== {len(out)} multi-layer Base64 strings in .rodata (layers>=2) ===")
for va,n,s,pr,o in out:
    print(f"  L{n} 0x{va:06x} refs={str(o):18s} {s[:52]:54s} -> {pr!r}")
print()
print("=== single-layer Base64 whose decode is printable ASCII (endpoints / class names) ===")
seen=set()
for m in B.finditer(raw[0x10000:0x18000]):
    va=0x10000+m.start();s=m.group(1)
    if len(s)%4: continue
    try: dd=base64.b64decode(s,validate=True)
    except Exception: continue
    if all(32<=c<127 for c in dd) and len(dd)>=4 and dd.decode() not in seen:
        seen.add(dd.decode())
        print(f"  0x{va:06x} refs={str(owners(va)):18s} {s.decode()[:44]:46s} -> {dd.decode()!r}")
