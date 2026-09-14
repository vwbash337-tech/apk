import re,base64,json,collections
raw=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
fm=json.load(open('analysis/funcmap.json'))
inv=collections.defaultdict(set)
for t,v in fm.items():
    for a in v['data_refs']: inv[a].add(int(t))
def owners(va,w=12):
    s=set()
    for d in range(-w,w+1): s|=inv.get(va+d,set())
    return tuple(sorted(s))
B=re.compile(rb'(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])')
def deep(s):
    cur=s;chain=[]
    for _ in range(8):
        try: dd=base64.b64decode(cur,validate=True)
        except Exception: break
        if not dd: break
        chain.append(dd)
        if not B.fullmatch(dd): break
        cur=dd
    return chain
res=[]
for m in B.finditer(raw[0x10000:0x18000]):
    va=0x10000+m.start();s=m.group(1)
    if len(s)%4: continue
    ch=deep(s)
    if not ch: continue
    # keep only chains whose final layer is printable OR hex-looking
    fin=ch[-1]
    if all(32<=c<127 for c in fin) and len(fin)>=3:
        res.append((va,len(ch),s.decode(),fin.decode(),owners(va)))
res=sorted(set(res),key=lambda x:x[0])
print(f"=== {len(res)} decoded plaintext strings from nested Base64 ===")
CAT=collections.defaultdict(list)
for va,L,s,fin,o in res:
    if fin.startswith('http') or fin.endswith('/') or 'instagram' in fin or 'graphql' in fin: CAT['ENDPOINT/URL'].append((va,L,s,fin,o))
    elif re.fullmatch(r'[0-9a-f]{32,128}',fin): CAT['HEX-SECRET (pin/key)'].append((va,L,s,fin,o))
    elif any(k in fin.lower() for k in ('frida','xposed','substrate','lsposed','su','magisk','maps','gum','deleted','zygisk','riru','edx','hook','debug','trace','emul','qemu','goldfish','bluestacks','nox','momo','ldplayer','genymotion','supervisor','daemonsu','busybox','test-keys','art.so','libc.so','bridge')): CAT['DETECTION TOKEN'].append((va,L,s,fin,o))
    else: CAT['OTHER'].append((va,L,s,fin,o))
for k in ('ENDPOINT/URL','HEX-SECRET (pin/key)','DETECTION TOKEN','OTHER'):
    print(f"\n--- {k} ({len(CAT[k])}) ---")
    for va,L,s,fin,o in CAT[k]:
        print(f"  L{L} 0x{va:06x} refs={str(o):22s} -> {fin!r}")
print("\n\n=== XOR-0x5A layer: printable decoded strings (non-base64) ===")
x=bytes(c^0x5a for c in raw[0x10000:0x18000])
seen=set()
for m in re.finditer(rb'[\x20-\x7e]{6,}',x):
    va=0x10000+m.start();s=m.group(0).decode()
    if s in seen: continue
    seen.add(s)
    if re.fullmatch(r'[A-Za-z0-9+/=]+',s) and len(s)%4==0:
        try:
            dd=base64.b64decode(s,validate=True)
            if len(dd) in (12,16,24,32): print(f"  0x{va:06x} refs={str(owners(va)):22s} {s!r} -> {len(dd)}B {dd.hex()}")
        except Exception: pass
print("\n=== plaintext literals referenced by the crypto funcs ===")
for t in (30,36,85,94,157,158,86,87,54,55,67,226,73,71,72,253,254,255,244,242,245,217,218,219):
    v=fm[str(t)]
    ds=[]
    for a in sorted(v['data_refs']):
        if 0x10000<=a<0x18000:
            m=re.match(rb'[\x20-\x7e]{3,}',raw[a:a+80])
            if m: ds.append((hex(a),m.group(0).decode()))
    if ds: print(f"  func#{t}: {ds[:8]}")
