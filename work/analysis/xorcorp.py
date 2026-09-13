import re,json,collections,base64
raw=open('apk_extracted/lib/arm64-v8a/libtopfollow.so','rb').read()
fm=json.load(open('analysis/funcmap.json'))
K=0x5a
x=bytes(c^K for c in raw)
inv=collections.defaultdict(set)
for t,v in fm.items():
    for a in v['data_refs']: inv[a].add(int(t))
# find printable runs in the XOR-decoded image inside .rodata
runs=[]
i=0x10000
while i<0x18000:
    if 32<=x[i]<127:
        j=i
        while j<0x18000 and 32<=x[j]<127: j+=1
        if j-i>=4:
            s=x[i:j].decode('latin1')
            runs.append((i,s))
        i=j
    else: i+=1
def owners(va,w=0):
    s=set()
    for d in range(-w,w+1): s|=inv.get(va+d,set())
    return tuple(sorted(s))
# keep only runs that are plausibly real (not the base64 alphabet / random)
good=[]
for va,s in runs:
    if re.fullmatch(r'[A-Za-z0-9+/]{20,}=?',s) and 'ABCDEFGH' in s: continue
    o=owners(va) or owners(va,3)
    good.append((va,s,o))
print(f"=== {len(good)} XOR-0x5A decoded runs in .rodata 0x10000-0x18000 (with owning funcs) ===")
for va,s,o in good:
    tag=''
    if re.fullmatch(r'[A-Za-z0-9+/]+={0,2}',s) and len(s)%4==0:
        try:
            dd=base64.b64decode(s,validate=True)
            if all(32<=c<127 for c in dd): tag=f"  =>b64 {dd.decode()!r}"
            else: tag=f"  =>b64 {dd.hex()}"
        except Exception: pass
    print(f"  0x{va:06x} refs={str(list(o))[:40]:42s} {s[:96]!r}{tag}")
